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

#### Invariant Protection: What Arkfile Never Discloses

The following assets are bound by strict client-side cryptography. They are never transmitted or stored in a form that is readable to the server, and they cannot be recovered by any level of server-side compromise:

- **User Password**: Standard credentials never reach the server, protected by OPAQUE, a Password-Authenticated Key Exchange (PAKE) protocol that allows a client to prove password ownership and authenticate without transmitting the password itself.
- **File Payloads**: Encrypted entirely client-side under a cryptographically random, per-file File Encryption Key (FEK) using AES-256-GCM.
- **File Metadata**: Original filenames and plaintext SHA-256 hashes are encrypted client-side under an Account Key derived solely on the client-side using the user's password.
- **Share Envelopes**: File details (e.g. key, filename, size) are wrapped inside an encrypted payload client-side that is only decryptable by a recipient who inputs the correct share password.

#### Compromise Scenarios and Impact Bounds

1. **Database-Only Leak**
   - **What is compromised**: The attacker gains the database tables (user metadata, encrypted share envelopes, rate-limiting audit logs, and encrypted user OPAQUE data).
   - **What remains secure**: All user passwords, file payloads, file metadata, and TOTP seeds remain completely confidential. Attacker cannot log in as any user or read any files.

2. **Database + Server Configuration Secret Leak**
   - **What is compromised**: Attacker gains the database plus the server's environment configuration (including `ARKFILE_MASTER_KEY`). They can forge session JSON Web Tokens (JWT) or read server identity keys.
   - **What remains secure**: File payloads, user passwords, file metadata, and TOTP configurations remain fully secure. All user-secret material (TOTP keys and contact info) remains encrypted and secure because the wrapping keys are derived from a filesystem-isolated master key file (`user-secret-master.bin`) protected by strict operating system user permissions. An attacker who steals a database backup and the server configuration secrets still cannot decrypt TOTP seeds or contact info because they lack access to this specific filesystem key file.

3. **Full Host and Root Compromise**
   - **What is compromised**: Attacker has live root access to the running machine. They can read variables in active memory, monitor server-side activity, observe user-secret material (such as TOTP keys and contact details), or actively attempt to inject malicious client code or manipulate future file encryption parameters.
   - **What remains secure**: User passwords can never be retrieved because OPAQUE authenticates without password transmission. Already uploaded file payloads remain completely undecryptable because the decryption keys are generated and held exclusively in client-side process or browser memory (RAM) during cryptographic operations, and are never transmitted. Authenticator backup codes cannot be reversed in bulk or recovered in cleartext because they are processed as one-way Argon2id hashes; since each backup code is generated using high-entropy rejection sampling (~59.5 bits of entropy), they resist offline brute-force attacks even under host compromise.
   - **Note on active attacks**: While a live root attacker can observe padded file sizes, upload timestamps, and active username handles, they cannot swap or substitute file segments without triggering an immediate authenticated-encryption verification failure on the client.

This separation ensures that compromise of one system does not affect the security of the other, providing defense in depth through independent cryptographic operations.

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
- No password-derived keys that require salt storage
- Session-based key derivation from OPAQUE authentication

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

### Multi-Key Encryption and Secure Sharing

**Multi-Key System:**
- Single file encrypted with multiple independent passwords
- File sharing without revealing primary password
- Unique encryption keys per share link
- Avoids file duplication through metadata management

**Sharing Mechanism:**
- Independent passwords for each share
- Expiration date controls
- Password hints for recipients
- Revocable share links

## Authentication System

### OPAQUE Protocol Implementation

Arkfile implements OPAQUE (Oblivious Pseudorandom Functions for Key Exchange), a Password-Authenticated Key Exchange (PAKE) protocol that provides superior security properties compared to traditional password authentication.

**OPAQUE Benefits:**
- Passwords never transmitted to server
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
- No password-derived salts stored server-side

**Resistance Properties:**
- Offline dictionary attack resistance
- Server compromise protection
- Pre-computation attack immunity
- Side-channel attack mitigation

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

- **Path A — Emergency one-shot login:** After OPAQUE login, the user submits a backup code at `POST /api/mfa/auth` with `is_backup: true`. The server validates and consumes the code, then issues a full access token. The enrolled second factor is unchanged; the user will need their normal TOTP code (or another backup code) on the next login.
- **Path B — Re-enroll with a backup code:** After OPAQUE login, the user consumes a backup code via `POST /api/mfa/recover-with-backup-code`, receives a short-lived `arkfile-mfa-reset` JWT, then calls `POST /api/mfa/reset` to stage new enrollment material and fresh backup codes. The user must complete MFA setup (`/api/mfa/verify`) before gaining full access.

**Credential Storage:**
TOTP secrets and WebAuthn credential records are encrypted with AES-256-GCM under a per-user key derived via HKDF-SHA256 from the user-secret master (`mfa_user` purpose). Backup codes are never stored in cleartext; only Argon2id hashes are persisted.

**WebAuthn credential blob (`method_type = webauthn`):** The decrypted `credential_data` value is a versioned JSON envelope `{ "v": 1, "credential": { ... }, "user_label": "..." }` where `credential` matches the `webauthn.Credential` record shape and `user_label` is an optional user-private printable-ASCII label (max 64 characters) never exposed to administrators. During pending enrollment before the security key ceremony completes, the blob may instead be the literal JSON object `{"pending":true}`.

### Password Validation and Security Requirements

Arkfile enforces different password requirements based on the authentication context. All requirements are defined in a single source of truth (`crypto/password-requirements.json`) and embedded at build time into both the Go server/CLI and the TypeScript client. Validation is deterministic: a password either meets the minimum length and character class requirements or it does not.

**Account and Custom Password Requirements:**
- Minimum 15 characters with at least 2 of 4 character classes (uppercase, lowercase, number, special character)
- Real-time validation provides immediate feedback during password creation
- Uses OPAQUE protocol providing complete zero-knowledge authentication

**Share Password Requirements:**
- Minimum 20 characters with at least 2 of 4 character classes (uppercase, lowercase, number, special character)
- Uses Argon2id with 128 MiB memory cost for anonymous access
- Limited attack surface affecting only shared files

**Validation Approach:**
The system uses a straightforward, deterministic check: passwords must meet the minimum length for their context and contain characters from at least 2 of the 4 character classes (uppercase letters, lowercase letters, numbers, special characters). This approach provides clear, predictable requirements that users can easily satisfy while still ensuring strong passwords through generous minimum lengths and the memory-hard Argon2id key derivation that makes brute-force attacks impractical.

### Password Contexts and Key Derivation

Arkfile uses the same account password for two completely independent purposes: OPAQUE authentication and file encryption key derivation. These two uses are cryptographically separated and never interact.

**Account Password for Authentication (OPAQUE).** The account password is used with the OPAQUE protocol to authenticate the user. OPAQUE performs a password-authenticated key exchange in which the client proves knowledge of the password without ever transmitting it. The server never learns the password at any point during registration or login. OPAQUE has its own internal key derivation and does not use Argon2id. The output of a successful OPAQUE authentication is a set of session keys used for JWT token issuance and session management.

**Account Password for File Encryption (Argon2id -> Account Key).** The same account password is used separately, entirely on the client side, to derive an Account Key via Argon2id. This Account Key serves as a Key Encryption Key (KEK). For each file, a cryptographically random 256-bit File Encryption Key (FEK) is generated, and the FEK is wrapped (encrypted) by the KEK using AES-256-GCM. The file data itself is encrypted with the FEK. The salt for this derivation is deterministic, computed as `SHA-256("arkfile-account-key-salt:{username}")`. This is safe because the Argon2id-derived key only wraps the FEK — the actual file encryption uses random FEKs with unique nonces, and the memory-hard properties of Argon2id protect the KEK even with a known salt.

**Custom Password for File Encryption (Argon2id -> Custom Key).** Users may optionally provide a custom password instead of using their account key to encrypt a file. This custom password goes through the same Argon2id derivation with a different deterministic salt (`SHA-256("arkfile-custom-key-salt:{username}")`), producing a Custom Key (KEK) that wraps the FEK. The encrypted envelope format distinguishes account-wrapped from custom-wrapped FEKs via a key type byte (0x01 for account, 0x02 for custom), so the client knows which password to request at decryption time.

**Share Password for Secure Sharing (Argon2id -> Share Key).** When a user creates a share link, a separate share password is required. Unlike account and custom passwords, share passwords use a random 32-byte salt (not deterministic). The share password is processed through Argon2id to derive a Share Key, which encrypts a Share Envelope containing the FEK, a download token, and file metadata (filename, size, SHA-256 hash). The encryption uses AES-GCM with Additional Authenticated Data (AAD = share_id + file_id) to cryptographically bind the envelope to a specific share. Recipients enter the share password, derive the same key, decrypt the envelope, extract the FEK, and decrypt the file. The share password is never sent to the server.

### Argon2id Key Derivation Parameters

All password-based key derivation contexts (account key, custom key, and share key) use the same unified Argon2id profile, defined as a single source of truth in `crypto/argon2id-params.json` and embedded at build time into both the Go server and the TypeScript client:

- **Variant:** Argon2id (resistant to both side-channel and GPU-based attacks)
- **Memory cost:** 128 MiB (131,072 KiB)
- **Time cost:** 4 iterations
- **Parallelism:** 1 thread
- **Output key length:** 32 bytes (256 bits)

These parameters exceed the strongest OWASP-recommended configuration for Argon2id (m=47,104 KiB / 46 MiB, t=1, p=1) as of 2026 by using significantly more memory and more iterations. Parallelism is set to 1 because the client-side key derivation runs in a browser WebAssembly context, which is single-threaded. Setting parallelism higher than 1 would not actually parallelize the computation in a browser — it would instead multiply the sequential work, increasing latency without improving security. With p=1 and t=4 at 128 MiB, the derivation is expected to take approximately 1–3 seconds in modern browsers, which is practical for interactive authentication while being extremely costly for attackers to brute-force.

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
├── opaque/               # OPAQUE server keys (never rotated)
├── jwt/                  # JWT signing keys (rotatable)
└── backup/               # Encrypted key backups
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

# OPAQUE key backup (monthly)
./scripts/maintenance/backup-keys.sh
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
- No client-side password hardening needed
- Mutual authentication with replay protection

**Session Validation:**
```bash
# Monitor active sessions
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/admin/sessions

# Revoke specific session
curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/admin/sessions/$SESSION_ID
```

## Monitoring and Alerting

Arkfile records security events without storing client IP addresses. Instead, each log entry contains an anonymised *entity ID* derived daily from a server-side HMAC key (see `logging/entity_id.go`). Events are written to the `security_events` table in the rqlite database and to structured JSON logs under `/var/log/arkfile/`. Administrators can stream or export these records into any external monitoring or alerting system as needed.

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

# Backup current state
./scripts/maintenance/backup-keys.sh

# Capture logs
sudo journalctl -u arkfile --since "1 hour ago" > incident-logs.txt
```

**Assessment Phase:**
```bash
# Run security audit
./scripts/maintenance/security-audit.sh

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
# User-secret master rotation only — see Key Rotation Procedures above

# Revoke all active sessions
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/admin/revoke-all-sessions

# Enable enhanced monitoring
sudo systemctl edit arkfile
# Add: [Service] Environment="LOG_LEVEL=debug"
```

### OPAQUE Server Key Rotation (admin-initiated re-registration)

OPAQUE server keys are the one key layer that cannot be re-wrapped in place: each `opaque_user_data` record is bound to the server key and OPRF seed present at registration, and the server never holds the password needed to re-wrap it. Rotating these keys is therefore a deliberate, guided operation in which affected users transparently re-register their OPAQUE record on their next sign-in. This is a routine administrative task suitable for periodic rotation (for example every 1–2 years); the same procedure also covers the rare case of a suspected key issue.

Re-registration never deletes the `users` row or any child rows. Files, shares, MFA enrollment, credits, contact info, and settings are all preserved: identity is the username (unchanged), and the Account Key is a deterministic function of username + password, so a user who re-registers with the same password regenerates a byte-identical Account Key and all account-wrapped files and metadata continue to decrypt. The clients confirm the password locally (by test-decrypting an account-key-encrypted metadata sample) before finalizing, so a mismatched password is never bound to the account.

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

**Weekly Tasks:**
```bash
# Security event review
./scripts/maintenance/security-audit.sh

# Key health verification
./scripts/maintenance/health-check.sh

# Authentication pattern analysis
rqlite -H localhost:4001 \
  "SELECT date(timestamp) as day, count(*) as attempts
   FROM security_events 
   WHERE timestamp > datetime('now', '-7 days')
   GROUP BY date(timestamp);"
```

**Monthly Tasks:**
```bash
# Comprehensive security assessment
./scripts/maintenance/security-audit.sh --comprehensive

# Key backup verification
./scripts/maintenance/backup-keys.sh --verify

# Performance security baseline
./scripts/testing/performance-benchmark.sh
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
# User-secret master rotation only — see Key Rotation Procedures above

# Security audit
./scripts/security-audit.sh

# Health check
curl http://localhost:8080/health

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
- **System Logs**: `/var/log/arkfile/`
- **Audit Logs**: Comprehensive event tracking in database

This security guide should be reviewed quarterly and updated based on emerging threats, security research, and operational experience.

For setup instructions, see [Setup Guide](setup.md). For API integration, see [API Reference](api.md).

---

## Support

Questions, comments or bug reports? Email **arkfile [at] pm [dot] me** / **arkfile [at] tutanota [dot] com** or open an issue on GitHub.  

Please avoid posting sensitive information in public issues.
