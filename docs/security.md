# Arkfile Security Guide

This document provides a comprehensive overview of Arkfile's security architecture, cryptographic design, and operational security procedures.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
   - [Security Model](#security-model)
   - [Defense in Depth](#defense-in-depth)
   - [Cryptographic Domain Separation](#cryptographic-domain-separation)
   - [Plain-Language Threat Model](#plain-language-threat-model)
2. [File Encryption System](#file-encryption-system)
3. [Authentication System](#authentication-system)
4. [Session Management](#session-management)
5. [Infrastructure Security](#infrastructure-security)
6. [Security Operations](#security-operations)
7. [Monitoring and Alerting](#monitoring-and-alerting)
8. [Incident Response](#incident-response)
10. [Threat Detection](#threat-detection)

## Architecture Overview

### Security Model

Arkfile's security model uses client-side encryption to ensure that user data remains protected from unauthorized access, including by service administrators. The system maintains strict cryptographic separation between two primary security domains: user authentication and file encryption.

### Plain-Language Threat Model

This section summarizes what Arkfile guarantees to protect and what can be recovered by adversaries across different system compromise levels.

#### Protected Data with a Trusted Client

The following assets are protected by client-side cryptography when the user runs an authentic Arkfile browser client or independently installed CLI. They are not transmitted to or stored by the server in plaintext. A passive server compromise or theft of stored server data does not by itself reveal them. A live attacker who controls the web origin can replace the browser client and capture passwords, keys, metadata, or file plaintext during future client operations; this active client-replacement threat is outside the protection provided by a web application served from the compromised origin.

- **User Password**: Standard credentials never reach the server, protected by OPAQUE, a Password-Authenticated Key Exchange (PAKE) protocol that allows a client to prove password ownership and authenticate without transmitting the password itself.
- **File Payloads**: Encrypted entirely client-side under a cryptographically random, per-file File Encryption Key (FEK) using AES-256-GCM.
- **File Metadata**: Original filenames, plaintext SHA-256 hashes, custom-password hints, and owner file tags are encrypted client-side under an Account Key derived solely on the client using the user's password. The server stores only opaque ciphertext and nonces for these fields. Tags are owner-only and are not included in share envelopes.
- **Share Envelopes**: File details (e.g. key, filename, size) are wrapped inside an encrypted payload client-side that is only decryptable by a recipient who inputs the correct share password.

#### Server-Visible Operational Metadata

Arkfile's zero-knowledge posture covers passwords, file contents, and encrypted owner metadata. It does not conceal every storage-accounting field from the Arkfile server. The following are intentionally known or computable by the server because billing, quotas, chunked download ranges, padding removal, export, and replication require them:

| Category | Examples | Why visible |
|----------|----------|-------------|
| Encrypted owner metadata | `encrypted_filename`, `encrypted_sha256sum`, `encrypted_password_hint`, `encrypted_tags` (plus nonces) | Opaque only; server cannot read plaintext. The AAD label `"encrypted_sha256sum"` binds the ciphertext of the plaintext-file SHA-256; do not confuse it with the stream digest below. Tags are owner-only Account Key ciphertext (AAD label `"encrypted_tags"`), absent from share envelopes; the server may observe tagged-vs-untagged presence, opaque blob size, and `tags_revision` edit count only. |
| Server plaintext digests | `encrypted_stream_sha256sum` (pre-padding client-encrypted stream), `stored_blob_sha256sum` (S3 object including padding) | Integrity and replication. Stream digest is returned on upload-complete as `encrypted_stream_sha256` and is omitted from owner file-metadata JSON. |
| Billable / storage accounting | upload `total_size`, `size_bytes`, `padded_size`, chunk count | User quota and projected billing use pre-padding encrypted `size_bytes`; provider stats and replication also use `padded_size` |
| Protocol / ownership | `owner_username`, plaintext `chunk_size_bytes`, `password_type`, FEK envelope key-type byte | Ownership, metadata AAD reconstruction, encrypted byte-range math, and account-vs-custom routing |

For a non-empty file, the canonical chunk count is `ceil(size_bytes / (chunk_size_bytes + 28))`, where 28 is the per-chunk AES-GCM overhead (nonce + tag). Plaintext length is then `size_bytes - (28 × chunk_count)`. Empty files use one chunk by convention. `size_bytes` is the pre-padding encrypted stream length, not the original plaintext file size. Server-generated padding obscures exact size from storage backends and outside observers of S3 objects; it does not hide size from the Arkfile server that received the pre-padding length at upload init.

#### Compromise Scenarios and Impact Bounds

1. **Database-Only Leak**
   - **What is compromised**: The attacker gains the database tables (user metadata, encrypted share envelopes, rate-limiting audit logs, and encrypted user OPAQUE data).
   - **What remains secure**: All user passwords, file payloads, file metadata, and TOTP seeds remain completely confidential. Attacker cannot log in as any user or read any files.

2. **Database + Server Configuration Secret Leak**
   - **What is compromised**: Attacker gains the database plus the server's environment configuration (including `ARKFILE_MASTER_KEY`). They can forge session JSON Web Tokens (JWT) or read server identity keys.
   - **What remains secure**: File payloads, user passwords, file metadata, and TOTP configurations remain fully secure. All user-secret material (TOTP keys and contact info) remains encrypted and secure because the wrapping keys are derived from a filesystem-isolated master key file (`user-secret-master.bin`) protected by strict operating system user permissions. An attacker who steals a database backup and the server configuration secrets still cannot decrypt TOTP seeds or contact info because they lack access to this specific filesystem key file.

3. **Full Host and Root Compromise**
   - **What is compromised**: Attacker has live root access to the running machine. They can read variables in active memory, monitor server-side activity, observe user-secret material (such as TOTP keys and contact details), or actively attempt to inject malicious client code or manipulate future file encryption parameters.
   - **What remains secure without client replacement**: Previously uploaded file payloads and encrypted owner metadata remain unavailable from server-side data alone because their decryption keys are held only by clients. OPAQUE does not expose account passwords during an authentic login exchange. Authenticator backup codes cannot be reversed in bulk or recovered in cleartext because they are processed as one-way Argon2id hashes; since each backup code is generated using high-entropy rejection sampling (~59.5 bits of entropy), they resist offline brute-force attacks.
   - **Active client-replacement limit**: A root attacker who changes the JavaScript or WASM served by the Arkfile origin can capture passwords, Account Keys, FEKs, metadata, and plaintext during subsequent browser operations. Such an attacker can also make the modified client accept attacker-chosen data. AES-GCM prevents an unmodified trusted client from accepting substituted encrypted chunks, but it cannot protect a client implementation controlled by the attacker. An independently installed and authenticated CLI has a separate software-distribution trust boundary.

Cryptographic domain separation prevents authentication outputs from serving as file-encryption keys and limits accidental cross-domain key reuse. It does not make a client immune to replacement or make every security domain unaffected by a full host compromise.

### Defense in Depth

Arkfile implements multiple layers of security:

1. **Transport Layer**: TLS 1.3 encryption for all communications
2. **Authentication**: OPAQUE password-authenticated key exchange (PAKE) with optional TOTP multi-factor authentication
3. **File Encryption**: AES-256-GCM with independent key derivation and multi-key support
4. **Key Management**: Secure key generation, storage, and rotation
5. **Access Control**: Role-based access with JWT token validation
6. **Client-Side Security**: TypeScript-based architecture with WebAssembly cryptographic operations
7. **Audit Logging**: Comprehensive security event tracking

### Cryptographic Domain Separation

```
┌─────────────────────────────────────────────────────────────┐
│                    ARKFILE SECURITY DOMAINS                 │
├─────────────────────────────────────────────────────────────┤
│  Authentication Domain (OPAQUE)                             │
│  ├── OPAQUE Server Private Key                              │
│  ├── User Authentication Envelopes                          │
│  └── Session Key Derivation                                 │
├─────────────────────────────────────────────────────────────┤
│  File Encryption Domain (Independent)                       │
│  ├── User-derived File Encryption Keys                      │
│  ├── AES-GCM Encrypted File Content                         │
│  └── Multi-key Envelope Support                             │
├─────────────────────────────────────────────────────────────┤
│  JWT Token Domain                                           │
│  ├── JWT Signing Keys (Rotatable)                           │
│  ├── Access Tokens                                          │
│  └── Refresh Tokens                                         │
└─────────────────────────────────────────────────────────────┘
```

## File Encryption System

### Cryptographic Implementation

The file encryption system uses secure key generation combined with AES-256-GCM for file encryption.

**Key Generation:**
- Cryptographically secure random key generation for each file
- Independent keys prevent cross-file compromise
- Per-file FEKs wrapped by an Account Key or Custom Key derived client-side with Argon2id
- File-encryption key derivation is independent of OPAQUE authentication and session keys

**AES-256-GCM Encryption:**
- 256-bit Advanced Encryption Standard
- Galois/Counter Mode for authenticated encryption
- Built-in integrity verification
- Unique initialization vectors for each operation

### File Processing and Integrity

**Version Control:**
- Version bytes embedded in encryption format
- Enables future cryptographic upgrades
- Maintains compatibility with existing data

**Integrity Verification:**
- SHA-256 checksums computed before encryption
- Verification performed after decryption
- Detects corruption or tampering
- Additional layer beyond AES-GCM authentication

**Chunked Processing:**
- Files split into 16MB segments for large file handling
- Reliable transfer mechanism
- Consistent encryption key per file across all chunks
- Memory-efficient processing

**Browser Download Paths:**
- Service Worker streaming is the preferred path and delivers decrypted chunks to the browser download manager with bounded application memory.
- A Blob fallback is retained for browsers and systems where Service Worker streaming is unavailable. It assembles the complete plaintext in browser-managed Blob storage before triggering the download and therefore uses resources proportional to file size.
- Both paths authenticate each encrypted chunk. The Blob path also verifies the whole-file plaintext digest before triggering the download, blocks the trigger and revokes the Blob URL on mismatch, and warns users when a large fallback download may exceed browser memory or storage limits.

### Multi-Key Encryption and Secure Sharing

**Multi-Key System:**
- Each file payload is encrypted once under a random per-file FEK
- The owner FEK envelope is wrapped by either the Account Key or a Custom Key
- Each share uses an independently password-derived Share Key to encrypt a share envelope containing the FEK
- Sharing does not reveal the account or custom file password and does not duplicate the encrypted file payload

**Sharing Mechanism:**
- Independent passwords for each share
- Expiration date controls
- Password hints for recipients
- Revocable share links

## Authentication System

### OPAQUE Protocol Implementation

Arkfile implements OPAQUE (Oblivious Pseudorandom Functions for Key Exchange), a Password-Authenticated Key Exchange (PAKE) protocol that provides superior security properties compared to traditional password authentication.

**OPAQUE Benefits:**
- Passwords are not included in authentic OPAQUE protocol messages
- Mutual authentication between client and server
- Resistance to offline dictionary attacks
- Protection against server compromise scenarios

**Three-Phase Process:**

1. **Registration Phase:**
   - Client generates cryptographic material
   - Server receives "envelope" without learning password
   - Envelope encrypted with password-derived keys

2. **Authentication Phase:**
   - Cryptographic handshake proves mutual authenticity
   - Client demonstrates password knowledge without revealing it
   - Server proves possession of legitimate authentication data

3. **Key Exchange:**
   - Secure session key establishment
   - Independent from file encryption keys
   - Ephemeral keys for forward secrecy

### OPAQUE Security Properties

**Protocol Security:**
- Password-blind key exchange prevents server learning passwords
- Mutual authentication ensures both parties are legitimate
- Forward secrecy through ephemeral session keys
- OPAQUE authentication state is independent of the public Account Key salt stored with each account

**Resistance Properties:** OPAQUE is designed to prevent a stolen server authentication record from becoming an ordinary password hash that can be tested offline. Its guarantees depend on the authentic protocol implementation and its assumptions; they do not protect passwords entered into a replaced browser client or make a fully compromised running host harmless.

### Multi-Factor Authentication (TOTP)

Arkfile provides TOTP-based multi-factor authentication as an additional security layer beyond OPAQUE. When enabled, users must complete both OPAQUE authentication and provide a valid TOTP code to access their accounts.

**TOTP Security Features:**
- RFC 6238 compliant implementation using HMAC-SHA1
- 30-second time windows with one-step tolerance for clock skew
- Cryptographically secure secret generation (160 bits entropy)
- Backup codes for account recovery (10 codes, single use, 10-character alphanumeric)
- Shared per-user failure lockout across TOTP and backup-code verification

**Authentication Flow Enhancement:**
When MFA is enabled, the OPAQUE login process returns a temporary token instead of full access credentials. This temporary token permits only MFA verification operations and expires after 10 minutes if unused. Upon successful MFA verification, the system issues full access and refresh tokens for normal operation.

**Backup Code Recovery (two paths):**
The system generates cryptographically secure backup codes during MFA setup. Each backup code is a 10-character alphanumeric string (~59.5 bits of entropy) hashed with Argon2id and stored single-use. Used backup codes are immediately invalidated and logged.

- **Path A -- Emergency one-shot login:** After OPAQUE login, the user submits a backup code at `POST /api/mfa/auth` with `is_backup: true`. The server validates and consumes the code, then issues a full access token. The enrolled second factor is unchanged; the user will need their normal TOTP code (or another backup code) on the next login.
- **Path B -- Re-enroll with a backup code:** After OPAQUE login, the user consumes a backup code via `POST /api/mfa/recover-with-backup-code`, receives a short-lived `arkfile-mfa-reset` JWT, then calls `POST /api/mfa/reset` to stage new enrollment material and fresh backup codes. The user must complete MFA setup (`/api/mfa/verify`) before gaining full access.

**Credential Storage:**
TOTP secrets and WebAuthn credential records are encrypted with AES-256-GCM under a per-user key derived via HKDF-SHA256 from the user-secret master (`mfa_user` purpose). Backup codes are never stored in cleartext; only Argon2id hashes are persisted.

**WebAuthn credential blob (`method_type = webauthn`):** The decrypted `credential_data` value is a versioned JSON envelope `{ "v": 1, "credential": { ... }, "user_label": "..." }` where `credential` matches the `webauthn.Credential` record shape and `user_label` is an optional user-private printable-ASCII label (max 64 characters) never exposed to administrators. During pending enrollment before the security key ceremony completes, the blob may instead be the literal JSON object `{"pending":true}`.

### Password Validation and Security Requirements

Arkfile enforces different password requirements based on the authentication context. All requirements are defined in a single source of truth (`crypto/password-requirements.json`) and embedded at build time into both the Go server/CLI and the TypeScript client. Validation is deterministic: a password either meets the minimum length and character class requirements or it does not.

**Account and Custom Password Requirements:**
- Minimum 15 characters with at least 2 of 4 character classes (uppercase, lowercase, number, special character)
- Real-time validation provides immediate feedback during password creation
- Uses OPAQUE password-authenticated key exchange without placing the password in authentic protocol messages

**Share Password Requirements:**
- Minimum 20 characters with at least 2 of 4 character classes (uppercase, lowercase, number, special character)
- Uses the unified Argon2id profile with a 64 MiB memory cost
- Limited attack surface affecting only shared files

**Validation Approach:**
The system uses a straightforward, deterministic check: passwords must meet the minimum length for their context and contain characters from at least 2 of the 4 character classes (uppercase letters, lowercase letters, numbers, special characters). This provides clear, predictable requirements, while Argon2id raises the cost of each guess against file and share key envelopes. These controls do not guarantee that a user-selected password has high entropy or make offline guessing impossible.

### Password Contexts and Key Derivation

Arkfile uses the same account password for two completely independent purposes: OPAQUE authentication and file encryption key derivation. These two uses are cryptographically separated and never interact.

**Account Password for Authentication (OPAQUE).** The account password is used with the OPAQUE protocol to authenticate the user. OPAQUE performs a password-authenticated key exchange in which an authentic client proves knowledge of the password without transmitting it in the protocol messages. The server does not learn the password during an authentic registration or login exchange. A compromised web origin can replace the browser client and capture the password before the OPAQUE exchange begins. OPAQUE has its own internal key derivation and does not use Argon2id. The output of a successful OPAQUE authentication is a set of session keys used for JWT token issuance and session management.

**Account Password for File Encryption (Argon2id -> Account Key).** The same account password is used separately, entirely on the client side, to derive an Account Key via Argon2id. The client generates a random 32-byte public Account Key salt during registration; the server stores that salt and KDF profile as account cryptographic metadata. Authenticated clients retrieve the metadata before deriving the Account Key. The Account Key serves as a Key Encryption Key (KEK). For each file, a cryptographically random 256-bit File Encryption Key (FEK) is generated, and the FEK is wrapped by the KEK using AES-256-GCM. The file payload itself is encrypted with the FEK. The public salt prevents deterministic reuse across deployments, but it does not prevent offline password guesses against a captured authenticated FEK envelope. AES-GCM authentication lets an attacker recognize a successful guess, so security against guessing depends on password strength and Argon2id cost.

**Custom Password for File Encryption (Argon2id -> Custom Key).** Users may optionally provide a custom password instead of using their Account Key to wrap a file's FEK. The client generates a new random 32-byte public salt for every custom-password file and derives a Custom Key under a separate KDF context. Reusing the same custom password for two files therefore does not reuse the Custom Key. The salt is carried in the authenticated owner FEK envelope. The same offline-guessing limitation described for the Account Key applies to captured custom-wrapped FEK envelopes.

**Share Password for Secure Sharing (Argon2id -> Share Key).** When a user creates a share link, a separate share password is required. Unlike account and custom passwords, share passwords use a random 32-byte salt (not deterministic). The share password is processed through Argon2id to derive a Share Key, which encrypts a Share Envelope containing the FEK, a download token, and file metadata (filename, size, SHA-256 hash). The encryption uses AES-GCM with Additional Authenticated Data (AAD = share_id + file_id) to cryptographically bind the envelope to a specific share. Recipients enter the share password, derive the same key, decrypt the envelope, extract the FEK, and decrypt the file. The share password is never sent to the server.

### Owner FEK Envelope and Offline Backup

Owner FEK envelope version 2 has a fixed 35-byte authenticated header: one version byte (`0x02`), one key-type byte (`0x01` account or `0x02` custom), one KDF-profile byte (`0x01`), and the 32-byte public salt. The header is followed by the 12-byte AES-GCM nonce and the wrapped 32-byte FEK with its 16-byte tag. AAD binds the file ID and complete header. Account envelopes must use the account's stored salt; custom envelopes use the per-file salt.

`.arkbackup` version 2 is self-describing. Its JSON metadata includes `owner_username`, `account_kdf_salt`, `account_kdf_profile`, file identifiers, encrypted owner metadata, the owner FEK envelope, and chunk parameters. The salt and profile are public, not secret key material. Offline decryption derives the Account Key from the password and bundle metadata without contacting the server. `owner_username` remains required inside the bundle because it is part of metadata AAD; a caller-supplied username is optional and must match.

### Argon2id Key Derivation Parameters

All password-based key derivation contexts (account key, custom key, and share key) use the same unified Argon2id profile, defined as a single source of truth in `crypto/argon2id-params.json` and embedded at build time into both the Go server and the TypeScript client:

- **Variant:** Argon2id (resistant to both side-channel and GPU-based attacks)
- **Memory cost:** 64 MiB (65,536 KiB)
- **Time cost:** 3 iterations
- **Parallelism:** 1 thread
- **Output key length:** 32 bytes (256 bits)

Parallelism is set to 1 because the client-side key derivation runs in a browser WebAssembly context that does not currently parallelize this operation. The profile is intended to remain practical on constrained supported clients while raising the cost of offline guesses. Actual latency and attacker cost depend on hardware and implementation, so the profile requires measurement across representative constrained and desktop devices rather than relying on an absolute strength claim.

## Session Management

### JWT Token System

ArkFile implements a **Netflix/Spotify-style authentication model** with enhanced security and performance characteristics:

**Token Architecture:**
- **30-minute access tokens**: Short-lived tokens for enhanced security
- **Automatic refresh at 25 minutes**: Proactive token renewal before expiration
- **Lazy revocation checking**: Revocation only checked during token refresh for optimal performance
- **Security-critical revocation**: Immediate revocation for critical security scenarios
- **Go/WASM client implementation**: High-performance client-side token management
- Secure storage with HttpOnly, Secure, SameSite=Strict cookies

**Session Security:**
- **Performance optimized**: Normal requests don't check revocation for maximum speed
- **Enhanced refresh cycle**: 30-minute token lifecycle with 25-minute refresh intervals
- Stateless and scalable token validation
- Cryptographically independent from file encryption
- Session keys derived from OPAQUE authentication
- Distributed deployment support

**Token Lifecycle Management:**
1. **Initial Authentication**: 30-minute token issued after OPAQUE authentication
2. **Automatic Refresh**: Client automatically refreshes token at 25-minute mark
3. **Lazy Revocation**: Revocation checking only performed during refresh operations
4. **Performance Optimization**: Normal API requests skip revocation checks for speed
5. **Security Edge Cases**: Critical revocations processed immediately when required

### Access Control and Rate Limiting

**Authorization Enforcement:**
- Application-level access control
- Principle of least privilege
- User-specific file access only
- Comprehensive rate limiting across all endpoints

**Rate Limiting Features:**
- Progressive penalty system with exponential backoff (30s → 60s → 2min → 4min → 8min → 15min → 30min cap)
- Brute force attack prevention with EntityID-based privacy protection
- Anonymous request tracking without storing IP addresses
- Advanced pattern detection for abuse mitigation

## Infrastructure Security

### Service Isolation

**User Account Security:**
- Dedicated, unprivileged `arkfile` service account
- Single unified user/group/service definition
- Limited system access and capabilities
- Proper file permissions and ownership

**Network Security:**
- TLS encryption for all communications
- Strong cipher suites and security headers
- Distributed rqlite database with TLS
- Authentication required for all operations

### Key Management Infrastructure

**Key Hierarchy:**
```
Root Security
├── OPAQUE Server Private Key (Long-term, stable)
├── JWT Signing Keys (Rotatable)
└── File Encryption Keys (User-derived)
```

**Storage Security:**
- Hardware security module (HSM) ready architecture
- Secure key generation and storage
- Automated key rotation capabilities
- Encrypted filesystem storage with proper permissions

**Backup and Recovery:**
- Secure backup procedures for critical keys
- Disaster recovery mechanisms
- Key integrity verification
- Strict access controls for backup materials

## Security Operations

### Cryptographic Key Management

**Key Storage Security:**
```bash
# Directory structure
/opt/arkfile/etc/keys/
├── opaque/               # OPAQUE server keys (guided user re-registration rotation)
└── jwt/                  # JWT signing keys (rotatable)
```

**File Permissions:**
- Key directories: 700 permissions
- Private keys: 600 permissions
- Owned by arkfile user and group
- No world-readable access

**Key Rotation Procedures:**
```bash
# User-secret master key rotation (requires admin MFA + brief downtime)
arkfile-admin login --username admin
arkfile-admin rotate-user-secret-master prepare --mandate-file /root/user-secret-rotation-mandate.txt --confirm
sudo systemctl stop arkfile
arkfile-admin rotate-user-secret-master apply --mandate-file /root/user-secret-rotation-mandate.txt --confirm
sudo systemctl start arkfile

# Or use the runbook wrapper (delegates to arkfile-admin only):
sudo ./scripts/maintenance/rotate-user-secret-master.sh

# Envelope master key rotation (re-wraps all system_keys rows; requires admin MFA + brief downtime)
arkfile-admin login --username admin
arkfile-admin rotate-envelope-master prepare --mandate-file /root/envelope-rotation-mandate.txt --confirm
sudo systemctl stop arkfile
arkfile-admin rotate-envelope-master apply --mandate-file /root/envelope-rotation-mandate.txt --confirm
sudo systemctl start arkfile

# Or use the runbook wrapper (delegates to arkfile-admin only):
sudo ./scripts/maintenance/rotate-envelope-master.sh

```

The envelope master key (`ARKFILE_MASTER_KEY` in `secrets.env`) wraps every secret in the `system_keys` table. Its rotation is fully server-side with no user impact: with the service stopped, the apply step decrypts each `system_keys` row under the old master and re-encrypts it under a freshly generated master in a single transaction, then rewrites the `ARKFILE_MASTER_KEY` line in `secrets.env`. Before committing, the new master is written to a root-only (0400) recovery file under `/opt/arkfile/backups/envelope-rotation/` and the whole `secrets.env` is backed up, so a failed swap is always recoverable. After the swap the entire table is verified to decrypt under the new master. The EntityID master is regenerated as part of the same rotation rather than carried forward, which resets the daily rate-limiting/correlation windows (a privacy improvement); no file data, sessions beyond the restart, or user secrets are affected.

JWT signing keys are managed in `system_keys` via KeyManager and support online, zero-downtime rotation with a verification overlap. Each tier (temp and full) is versioned; the active signing version is recorded in a `system_keys` metadata row, and every version still present is accepted for verification until its tokens expire. Rotate with `arkfile-admin rotate-jwt-keys rotate --confirm` (issues a new active version for both tiers and reloads the server's in-memory key rings), then `arkfile-admin rotate-jwt-keys retire --version N --confirm` once the access-token lifetime has elapsed to drop the superseded version.

### Server secret hierarchy and user recovery
Arkfile partitions system secrets into separate trust layers (envelope master, operational, server-identity, and the user-secret master). The user-secret master holds user-secret-wrapping keys (`mfa_user` and `contact_info` purpose keys derived via HKDF-SHA256 from the `/opt/arkfile/etc/keys/user-secret-master.bin` file with 0400 owner-only permissions).

**In-Memory Hardening:**
- System loader pins the user-secret master key using POSIX `mlock` to disable memory swapping of keys to disk storage.
- Key pages are marked on initialization using `madvise(..., MADV_DONTDUMP)` to ensure they won't leak into core logs.
- Disables process-wide core dumps entirely using `prctl(PR_SET_DUMPABLE, 0)`.

**Lost-Device User Recovery Model:**
- Lost password = lost files. Lost authenticator + lost backup codes = lost account. This model is intentionally non-custodial.
- If a user loses their authenticator (TOTP), but holds one of their 10 alphanumeric backup codes (~59.5 bits of secure entropy sampled using rejection sampling), they can use path A (emergency one-shot login) or path B (re-enroll with a backup code). See the MFA section above.
- Path B recovery issues a short-lived temporary `"arkfile-mfa-reset"` JWT claim. Users use this reset-authorized context to flush, reset, and re-setup their MFA keys immediately without requiring administrative intervention.
- **Admin-assisted full reset (total lockout):** When a user has lost both their enrolled second factor and all backup codes, an operator with admin + MFA authentication runs `arkfile-admin reset-user-mfa --username USER --confirm` (from localhost via the admin API). This deletes all MFA credential rows, backup codes, and MFA usage logs; force-logouts all sessions; and leaves the account in `requires_mfa_setup` on next password login. User contact info is **not** deleted. The CLI displays on-file contact info before reset; if none exists, `--acknowledge-no-contact-info` is required. Request body accepts optional `credential_id` / `label` for future credential-scoped reset; v1 rejects non-empty values.

### Authentication Security

**OPAQUE Protocol Security:**
- Pure OPAQUE registration and authentication flow
- OPAQUE blinding prevents password transmission
- OPAQUE authentication does not use the file-encryption Argon2id path
- Mutual authentication with replay protection

## Monitoring and Alerting

Arkfile records security events without persisting client IP addresses. Instead, each event contains an anonymised entity ID derived from a server-side HMAC key (see `logging/entity_id.go`). Structured event records are written to the `security_events` table; concise event summaries and application logs are emitted to the service logger and normally collected by systemd-journald. Arkfile does not currently provide a complete automated alerting or incident-response system. The event categories and response intervals below are operational recommendations for deployers.

### Security Event Categories

**Critical Events (Immediate Response):**
- Multiple authentication failures from single entity
- Suspicious access patterns
- Key file modifications
- Emergency procedure activations
- Database integrity failures

**Warning Events (Review Within Hours):**
- Rate limit violations
- JWT refresh failures
- Configuration changes
- Unusual file access patterns

**Info Events (Daily Review):**
- Successful authentications
- Key health checks
- System startup/shutdown
- Routine maintenance operations

### Security Event Logging

**Event Tracking:**
- Authentication attempts with entity ID anonymization
- Rate limiting triggers and violations
- Potential abuse pattern detection
- System configuration changes
- Emergency procedure activations

**Log Analysis:**
```bash
# View recent critical events
rqlite -H localhost:4001 \
  "SELECT * FROM security_events WHERE severity='CRITICAL' 
   AND timestamp > datetime('now', '-24 hours');"

# Analyze authentication patterns
rqlite -H localhost:4001 \
  "SELECT entity_id, count(*) as attempts
   FROM security_events 
   WHERE event_type LIKE '%login%' 
   GROUP BY entity_id 
   HAVING attempts > 10;"
```

### Logs and Event Access
```bash
# Show critical events from the last hour
rqlite -H localhost:4001 \
  "SELECT * FROM security_events WHERE severity='CRITICAL' \
   AND timestamp > datetime('now', '-1 hour');"
```

## Incident Response

### Security Incident Classification

**Severity Levels:**

1. **Critical (Immediate Response):**
   - Key compromise suspected
   - Active brute force attack
   - Database integrity failure
   - Authentication bypass detected

2. **High (Response within 2 hours):**
   - Suspicious access patterns
   - Rate limiting failures
   - Configuration tampering
   - Service availability issues

3. **Medium (Response within 24 hours):**
   - Policy violations
   - Unusual usage patterns
   - Performance degradation
   - Audit compliance issues

### Emergency Response Procedures

**Immediate Actions:**
```bash
# Stop service if compromise suspected
sudo systemctl stop arkfile

# Capture logs
sudo journalctl -u arkfile --since "1 hour ago" > incident-logs.txt
```

Preserve a read-only copy of the deployment's data, key files, and configuration using the operator's established backup procedure before changing state.

**Assessment Phase:**
```bash
# Check file integrity
find /opt/arkfile/etc/keys -type f -exec sha256sum {} \; > file-hashes.txt

# Analyze recent security events
rqlite -H localhost:4001 \
  "SELECT * FROM security_events 
   WHERE timestamp > datetime('now', '-24 hours') 
   ORDER BY severity DESC, timestamp DESC;"
```

**Containment Actions:**
```bash
# Rotate JWT keys immediately
# User-secret master rotation only -- see Key Rotation Procedures above

# Enable enhanced monitoring
sudo systemctl edit arkfile
# Add: [Service] Environment="LOG_LEVEL=debug"
```

Debug logging may reveal additional operational context and should be enabled only for a bounded incident investigation, never as a normal production setting. Session revocation should use the implemented administrator CLI operation appropriate to the affected account or key rotation; Arkfile does not expose an unauthenticated generic incident endpoint.

### OPAQUE Server Key Rotation (admin-initiated re-registration)

OPAQUE server keys are the one key layer that cannot be re-wrapped in place: each `opaque_user_data` record is bound to the server key and OPRF seed present at registration, and the server never holds the password needed to re-wrap it. Rotating these keys is therefore a deliberate, guided operation in which affected users transparently re-register their OPAQUE record on their next sign-in. This is a routine administrative task suitable for periodic rotation (for example every 1–2 years); the same procedure also covers the rare case of a suspected key issue.

Re-registration never deletes the `users` row or any child rows. Files, shares, MFA enrollment, credits, contact info, settings, and the public Account Key salt and KDF profile are preserved. A user who re-registers with the same password therefore regenerates the same Account Key, so account-wrapped files and metadata continue to decrypt. The clients confirm the password locally by test-decrypting an Account-Key-encrypted metadata sample before finalizing, so a mismatched password is never bound to the account.

**Rotate for the whole deployment (recommended atomic flow):**

```bash
# Flags every active account, clears opaque_user_data, replaces server keys,
# reloads them in the running service, and force-logs-out all sessions.
# ORDER IS LOAD-BEARING: do not replace OPAQUE server keys before flagging
# accounts, or users will see a generic authentication failure instead of the
# guided re-registration prompt.
arkfile-admin rotate-opaque-keys rotate --confirm
```

Or use the runbook wrapper: `bash scripts/maintenance/rotate-opaque-keys.sh`

**Two-step flow (only if you need to separate flagging from key replacement):**

```bash
# Step 1: Flag every active account FIRST.
arkfile-admin flag-user-reregistration --all --confirm

# Step 2: Replace server keys only after every account is flagged and
# opaque_user_data is empty. This step refuses to run if ordering is wrong.
arkfile-admin rotate-opaque-keys replace-keys --confirm
```

Do not run key replacement before step 1. The `replace-keys` subcommand enforces that every active account is flagged and that no `opaque_user_data` rows remain; the atomic `rotate` subcommand performs both steps in the correct order automatically.

On their next login, each user is met with a clear, structured prompt (HTTP 409 `account_requires_reregistration`) and is guided through the re-registration ceremony within the same login attempt, continuing into their existing MFA. To rotate a single account instead, use:

```bash
arkfile-admin flag-user-reregistration --username USER --confirm
```

## Audit Trails  
Arkfile is pre-release software and **has no formal security certifications**.  
The features below describe on-disk logging and in-app event tracking only.

### Audit Trail Requirements

**Required Audit Events:**
- All authentication attempts (success/failure)
- Key management operations
- Administrative actions
- Configuration changes
- Emergency procedures
- Data access patterns

**Audit Log Retention:**
- Security Events: 90 days minimum
- Authentication Logs: 1 year
- Key Management: 7 years
- Emergency Procedures: Permanent

### Regular Audit Procedures

The following SQL is an example manual review. Arkfile does not currently ship the referenced audit, health-check, or key-backup automation scripts, so deployers must supply and validate their own operational backup and alerting procedures.

**Weekly Tasks:**
```bash
# Authentication pattern analysis
rqlite -H localhost:4001 \
  "SELECT date(timestamp) as day, count(*) as attempts
   FROM security_events 
   WHERE timestamp > datetime('now', '-7 days')
   GROUP BY date(timestamp);"
```

## Threat Detection

### Attack Pattern Recognition

**Brute Force Detection:**
```bash
# Monitor authentication failure patterns
rqlite -H localhost:4001 \
  "SELECT entity_id, count(*) as failures
   FROM security_events 
   WHERE event_type='opaque_login_failure'
   AND timestamp > datetime('now', '-24 hours')
   GROUP BY entity_id
   HAVING count(*) > 10;"
```

**Credential Stuffing Detection:**
```bash
# Detect rapid attempts across multiple accounts
rqlite -H localhost:4001 \
  "SELECT entity_id, count(DISTINCT username) as unique_users
   FROM security_events 
   WHERE event_type IN ('opaque_login_failure', 'opaque_login_success')
   AND timestamp > datetime('now', '-1 hour')
   GROUP BY entity_id
   HAVING unique_users > 5;"
```

**Suspicious Access Patterns:**
```bash
# Identify unusual file access patterns
rqlite -H localhost:4001 \
  "SELECT username, count(*) as file_accesses
   FROM security_events 
   WHERE event_type='file_access'
   AND timestamp > datetime('now', '-1 hour')
   GROUP BY username
   HAVING file_accesses > 100;"
```

### Automated Threat Response

**Dynamic Rate Limiting:**
```bash
# Adaptive rate limiting based on threat level
THREAT_LEVEL=$(rqlite -H localhost:4001 \
  "SELECT CASE 
     WHEN count(*) > 100 THEN 'HIGH'
     WHEN count(*) > 50 THEN 'MEDIUM'
     ELSE 'LOW'
   END
   FROM security_events 
   WHERE event_type='rate_limit_violation'
   AND timestamp > datetime('now', '-1 hour')")

# Adjust rate limits based on threat level
case "$THREAT_LEVEL" in
    "HIGH")   # Aggressive rate limiting
        curl -X POST http://localhost:8080/admin/rate-limit \
          -d '{"requests_per_hour": 10, "burst": 5}' ;;
    "MEDIUM") # Enhanced rate limiting  
        curl -X POST http://localhost:8080/admin/rate-limit \
          -d '{"requests_per_hour": 50, "burst": 10}' ;;
    "LOW")    # Normal rate limiting
        curl -X POST http://localhost:8080/admin/rate-limit \
          -d '{"requests_per_hour": 100, "burst": 20}' ;;
esac
```

**Entity Blocking Automation:**
```bash
# Automatic blocking for severe violations
MALICIOUS_ENTITIES=$(rqlite -H localhost:4001 \
  "SELECT entity_id FROM security_events 
   WHERE event_type='opaque_login_failure'
   AND timestamp > datetime('now', '-1 hour')
   GROUP BY entity_id
   HAVING count(*) > 50")

for entity in $MALICIOUS_ENTITIES; do
    logger "Blocking entity: $entity for excessive failures"
    # Implement entity blocking logic
done
```

### Security Metrics and KPIs

**Key Performance Indicators:**
- **Authentication Success Rate**: >95%
- **Average Response Time**: <500ms
- **False Positive Rate**: <1%
- **Mean Time to Detection**: <15 minutes
- **Mean Time to Response**: <2 hours

**Security Dashboard Generation:**
```bash
# Generate security metrics report
DATE=$(date +"%Y-%m-%d")
echo "Arkfile Security Metrics Report - $DATE"

# Authentication metrics (Last 24 hours)
echo "Authentication Metrics:"
rqlite -H localhost:4001 \
  "SELECT 
    'Total Attempts: ' || count(*),
    'Successful: ' || sum(case when event_type='opaque_login_success' then 1 else 0 end),
    'Success Rate: ' || printf('%.2f%%', 
      100.0 * sum(case when event_type='opaque_login_success' then 1 else 0 end) / count(*)
    )
   FROM security_events 
   WHERE event_type IN ('opaque_login_success', 'opaque_login_failure')
   AND timestamp > datetime('now', '-24 hours');"

# Rate limiting metrics
echo "Rate Limiting Violations:"
rqlite -H localhost:4001 \
  "SELECT count(*) FROM security_events 
   WHERE event_type='rate_limit_violation'
   AND timestamp > datetime('now', '-24 hours');"

# Top security events (Last 7 days)
echo "Top Security Events:"
rqlite -H localhost:4001 \
  "SELECT event_type, count(*) as occurrences
   FROM security_events 
   WHERE timestamp > datetime('now', '-7 days')
   GROUP BY event_type
   ORDER BY count(*) DESC
   LIMIT 10;"
```

## Example Emergency Contacts and Escalation

### Security Team Contacts

### Escalation Matrix
1. **Level 1**: System Administrator (Response: 30 minutes)
2. **Level 2**: Security Team Lead (Response: 2 hours)
3. **Level 3**: Security Director (Response: 4 hours)
4. **Level 4**: Executive Team (Response: 24 hours)

---

## Quick Reference

### Critical Security Commands
```bash
# Emergency service stop
sudo systemctl stop arkfile

# Emergency key rotation
# User-secret master rotation only -- see Key Rotation Procedures above

# Health check
curl http://localhost:8080/healthz

# View recent critical events
rqlite -H localhost:4001 \
  "SELECT * FROM security_events WHERE severity='CRITICAL' 
   AND timestamp > datetime('now', '-1 hour');"
```

### Security Properties
- **Forward Secrecy**: Ephemeral session keys
- **Server Impersonation Protection**: OPAQUE mutual authentication
- **Replay Attack Prevention**: Protocol-level nonce handling
- **Domain Separation**: Independent cryptographic contexts

### Log Locations
- **Application Logs**: `sudo journalctl -u arkfile`
- **Security Events**: rqlite database table `security_events`
- **Audit Scope**: Implemented structured security events and administrator action records in the database; this is not a formal compliance audit system

This security guide should be reviewed quarterly and updated based on emerging threats, security research, and operational experience.

For setup instructions, see [Setup Guide](setup.md). For API integration, see [API Reference](api.md).

---

## Support

Questions, comments or bug reports? Email **arkfile [at] pm [dot] me** / **arkfile [at] tutanota [dot] com** or open an issue on GitHub.  

Please avoid posting sensitive information in public issues.
