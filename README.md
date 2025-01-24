# Arkfile

*s3-style encrypted file backup*

## High-Level Architecture

### Components

1. **Client-Side**
   - Web interface for user interaction
   - WebAssembly (WASM) module for client-side encryption/decryption
   - JavaScript for WASM interaction and API calls

2. **Server-Side**
   - Go HTTP server (Echo framework)
   - JWT authentication
   - SQLite database for user data and file metadata
   - Integration with Backblaze B2 (via MinIO client) for file storage

3. **External Services**
   - Backblaze B2 for encrypted file storage
   - Caddy web server for TLS and reverse proxy

### Security Features

- Client-side encryption using user passwords
- Password hints stored separately from encrypted files
- JWT-based authentication
- TLS encryption for all traffic
- Secure key derivation (PBKDF2)

## Directory Structure

```
/opt/arkfile/
├── bin/                    # Application binaries
├── etc/                    # Configuration
│   ├── prod/              # Production configuration
│   └── test/              # Test configuration
├── var/
│   ├── lib/               # Application data
│   │   ├── prod/         # Production data
│   │   └── test/         # Test data
│   ├── log/              # Log files
│   └── run/              # Runtime files
├── webroot/               # Static files and WASM
└── releases/              # Versioned releases
    ├── YYYYMMDD_HHMMSS/  # Timestamped releases
    └── current -> ...     # Symlink to current release
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
   - Backblaze B2 integration
   - File storage operations

5. **`auth/jwt.go`**
   - JWT token generation and validation
   - Authentication middleware

6. **`database/database.go`**
   - Database connection setup
   - Schema creation
   - File metadata storage

## Environment Variables

Environment-specific variables are stored in `/opt/arkfile/etc/<env>/secrets.env`:

```
BACKBLAZE_ENDPOINT=...
BACKBLAZE_KEY_ID=...
BACKBLAZE_APPLICATION_KEY=...
BACKBLAZE_BUCKET_NAME=...
JWT_SECRET=...
VULTR_API_KEY=...
PROD_PORT=... # e.g. 8080
TEST_PORT=... # e.g. 8081
CADDY_EMAIL=...
```

## Build and Deployment

1. **Initial Setup**
   ```bash
   # Setup service users and directories
   ./scripts/setup-users.sh
   ./scripts/setup-directories.sh
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
   - Client-side encryption
   - Secure key derivation
   - Password hints

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

The application follows a clean architecture pattern with clear separation of concerns, making it maintainable and scalable. Each component has a single responsibility, and dependencies flow inward from external services to the core business logic.

For questions/comments/support, either file an issue on GitHub, or during alpha testing stage, you can email `arkfile [at] pm [dot] me`.

(Do not include sensitive or personal information in any public GitHub issue.)

---

*make yourself an ark of cypress wood*
