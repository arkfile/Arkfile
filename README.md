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
   - rqlite distributed database
   - S3-compatible object storage via:
     - External providers (Backblaze B2, Wasabi, or Vultr), or
     - Local MinIO storage, or
     - MinIO distributed cluster

3. **External Services**
   - S3-compatible storage providers (Backblaze B2, Wasabi, or Vultr)
   - Caddy web server for TLS and reverse proxy
   - rqlite database cluster

### Security Features

- Client-side encryption using quantum-resistant SHAKE-256 for key derivation
- Choice between account password or file-specific password for encryption
- SHA-256 checksums for file integrity verification
- Distributed database with authentication and TLS
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
   - rqlite cluster connection setup
   - Schema creation and management
   - File metadata storage
   - Distributed query handling

## Environment Variables

Environment-specific variables are stored in `/opt/arkfile/etc/<env>/secrets.env`:

```
# Storage Provider Configuration
STORAGE_PROVIDER=...  # backblaze, wasabi, vultr, local, or cluster

# For S3-Compatible Providers (backblaze, wasabi, vultr)
S3_ENDPOINT=...       # Required for Backblaze
S3_REGION=...         # Required for Wasabi/Vultr
S3_ACCESS_KEY_ID=... 
S3_SECRET_KEY=...
S3_BUCKET_NAME=...

# For Local MinIO Storage (when STORAGE_PROVIDER=local)
LOCAL_STORAGE_PATH=... # Path to store data (e.g., /opt/arkfile/var/lib/prod/minio/data)
MINIO_ROOT_USER=...    # Override default MinIO credentials if needed
MINIO_ROOT_PASSWORD=... # Override default MinIO credentials if needed

# For MinIO Cluster (when STORAGE_PROVIDER=cluster)
MINIO_CLUSTER_NODES=...        # Comma-separated list of node addresses
MINIO_CLUSTER_ACCESS_KEY=...   # Cluster authentication
MINIO_CLUSTER_SECRET_KEY=...   # Cluster authentication
MINIO_CLUSTER_BUCKET=...       # Default bucket name (defaults to "arkfile")

# Database Configuration
RQLITE_NODES=...      # Comma-separated list of rqlite nodes
RQLITE_USERNAME=...   # rqlite authentication username
RQLITE_PASSWORD=...   # rqlite authentication password

# Other Configuration
JWT_SECRET=...
VULTR_API_KEY=...    # For Caddy DNS challenges
PROD_PORT=...        # e.g. 8080
TEST_PORT=...        # e.g. 8081
CADDY_EMAIL=...
```

## Storage Provider Support

The application supports multiple storage providers:

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

4. **Local MinIO Storage**
   - Set `STORAGE_PROVIDER=local`
   - Uses MinIO in filesystem mode for local data storage
   - Requires `LOCAL_STORAGE_PATH` to specify storage location
   - Ideal for testing, development, or self-hosted environments
   - Configured with `MINIO_ROOT_USER` and `MINIO_ROOT_PASSWORD` (defaults to minioadmin/minioadmin)

5. **MinIO Cluster**
   - Set `STORAGE_PROVIDER=cluster`
   - Uses MinIO in distributed mode across multiple nodes
   - Requires `MINIO_CLUSTER_NODES` (comma-separated list of node addresses)
   - Authentication via `MINIO_CLUSTER_ACCESS_KEY` and `MINIO_CLUSTER_SECRET_KEY`
   - Custom bucket name configurable via `MINIO_CLUSTER_BUCKET` (defaults to "arkfile")
   - Provides high-availability and scale-out object storage solution

## Build and Deployment

1. **Initial Setup**
   ```bash
   # Setup service users and directories
   ./scripts/setup-users.sh
   ./scripts/setup-directories.sh

   # Setup rqlite cluster
   ./scripts/setup-rqlite.sh
   
   # Setup MinIO (for local or cluster storage options)
   ./scripts/setup-minio.sh
   ```

2. **Storage Configuration**
   ```bash
   # For local storage:
   # Edit /opt/arkfile/etc/<env>/secrets.env and set:
   # STORAGE_PROVIDER=local
   # LOCAL_STORAGE_PATH=/opt/arkfile/var/lib/<env>/minio/data
   # Optional: MINIO_ROOT_USER and MINIO_ROOT_PASSWORD if not using defaults

   # For cluster storage:
   # Edit /opt/arkfile/etc/<env>/secrets.env and set:
   # STORAGE_PROVIDER=cluster
   # MINIO_CLUSTER_NODES=node1:9000,node2:9000,node3:9000
   # MINIO_CLUSTER_ACCESS_KEY and MINIO_CLUSTER_SECRET_KEY
   # Optional: MINIO_CLUSTER_BUCKET if not using default "arkfile"
   
   # Start MinIO service
   sudo systemctl start minio@<env>
   
   # Enable MinIO service
   sudo systemctl enable minio@<env>
   ```

3. **Build Process**
   ```bash
   # Build for all environments
   ./scripts/build.sh
   ```

4. **Deployment**
   ```bash
   # Deploy to production
   ./scripts/deploy.sh prod

   # Deploy to test environment
   ./scripts/deploy.sh test
   ```

5. **Rollback (if needed)**
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
   - Distributed database with authentication and TLS
   - Data replication across cluster nodes
   - Password hints stored separately from encrypted files

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

2. **Environment Separation**
   - Production and test environments use separate services
   - Each environment has its own rqlite cluster
   - Secrets stored in environment-specific files
   - Different service users for different environments

3. **Database Security**
   - rqlite authentication required for all operations
   - Separate credentials per environment
   - TLS encryption for database communication
   - Automatic leader election and failover

## Monitoring and Maintenance

1. **Service Management**
   ```bash
   # Check application status
   systemctl status arkfile@prod
   systemctl status arkfile@test

   # Check database cluster status
   systemctl status rqlite@prod
   systemctl status rqlite@test
   
   # Check MinIO storage status (when using local or cluster storage)
   systemctl status minio@prod
   systemctl status minio@test

   # View application logs
   journalctl -u arkfile@prod -f
   journalctl -u arkfile@test -f

   # View database logs
   journalctl -u rqlite@prod -f
   journalctl -u rqlite@test -f
   
   # View MinIO logs
   journalctl -u minio@prod -f
   journalctl -u minio@test -f
   ```

2. **Release Management**
   - Releases are automatically cleaned up (keeping last 5)
   - Each release is versioned and timestamped
   - Rollback markers track deployment history

3. **Database Management**
   - rqlite cluster with automatic leader election
   - Data replicated across cluster nodes
   - Automatic failover and recovery
   - Each environment has separate cluster nodes

---

## Support & Security

For questions, comments or support, either file an issue on GitHub, or during alpha testing stage, you can email `arkfile [at] pm [dot] me`.

For security issues, please email first and allow time to review the findings before creating a GitHub issue: `arkfile [at] pm [dot] me`.

(Do not include sensitive or personal information in any public GitHub issue.)

---

*make yourself an ark of cypress wood*
