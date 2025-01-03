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

## Data Flow

1. **File Upload**
   ```
   Client → Client-side Encryption (WASM)
   → Server (Echo) → Backblaze B2
                   → SQLite (metadata)
   ```

2. **File Download**
   ```
   Client → Server Request
   → Server (Echo) → Backblaze B2 (encrypted file)
                   → SQLite (password hint)
   → Client → Client-side Decryption (WASM)
   ```

## Environment Variables
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

1. **Build Process**
   - Compile server-side Go code
   - Compile client-side Go code to WASM
     - `cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" client/`
     - `cd client/`
     - `GOOS=js GOARCH=wasm go build -o main.wasm`
   - Bundle static assets

2. **Deployment**
   - Set up Vultr server with Rocky Linux (expect RAM to be the bottleneck on max file upload size)
   - Configure firewall
   - Configure Backblaze bucket, API keys
   - `git clone` this repo down into `/opt/arkfile-test/` or `/opt/arkfile/`
   - Copy .env.example to .env, generate JWT secret, fill in any missing secrets/credentials
   - Add `export MY_ENV_VAR=<SOME VALUE>` for each variable required to `~/.bashrc`, then run `source ~/.bashrc`
   - Configure Caddy for TLS
   - Set up systemd services

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

The application follows a clean architecture pattern with clear separation of concerns, making it maintainable and scalable. Each component has a single responsibility, and dependencies flow inward from external services to the core business logic.

For questions/comments/support, either file an issue on GitHub, or during alpha testing stage, you can email `arkfile [at] pm [dot] me`.

(Do not include sensitive or personal information in any public GitHub issue.)

---

*make yourself an ark of cypress wood*

