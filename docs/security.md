# Arkfile Security Guide

This document provides a comprehensive overview of Arkfile's security architecture, cryptographic design, and operational security procedures.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [File Encryption System](#file-encryption-system)
3. [Authentication System](#authentication-system)
4. [Session Management](#session-management)
5. [Infrastructure Security](#infrastructure-security)
6. [Security Operations](#security-operations)
7. [Monitoring and Alerting](#monitoring-and-alerting)
8. [Incident Response](#incident-response)
9. [Compliance and Auditing](#compliance-and-auditing)
10. [Threat Detection](#threat-detection)

## Architecture Overview

### Security Model

Arkfile's security model uses client-side encryption to ensure that user data remains protected from unauthorized access, including by service administrators. The system maintains strict cryptographic separation between two primary security domains: user authentication and file encryption.

This separation ensures that compromise of one system does not affect the security of the other, providing defense in depth through independent cryptographic operations.

### Defense in Depth

Arkfile implements multiple layers of security:

1. **Transport Layer**: TLS 1.3 encryption for all communications
2. **Authentication**: OPAQUE password-authenticated key exchange (PAKE)
3. **File Encryption**: AES-256-GCM with independent key derivation
4. **Key Management**: Secure key generation, storage, and rotation
5. **Access Control**: Role-based access with JWT token validation
6. **Audit Logging**: Comprehensive security event tracking

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

The file encryption system uses a two-layer approach combining Argon2ID for key derivation with AES-256-GCM for file encryption.

**Argon2ID Key Derivation:**
- Memory-hard key derivation function
- Protection against brute-force attacks
- GPU and ASIC-resistant design
- Parameters: 4 iterations, 128MB memory usage, 4 threads of parallelism

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

### Hybrid Argon2ID-OPAQUE Architecture

**Client-Side Hardening:**
- Argon2ID applied before OPAQUE processing
- Adaptive parameters based on device capabilities
- Protection against ASIC and GPU attacks
- Maintains usability across device types

**Server-Side Hardening:**
- Additional Argon2ID applied to OPAQUE envelopes
- Maximum parameters (128MB memory, 4 iterations, 4 threads)
- Prevents credential stuffing attacks
- Establishes minimum computational costs

### Device-Adaptive Security Parameters

**Device Profiles:**
- **Interactive**: 32MB memory, 1 iteration, 2 threads (mobile devices)
- **Balanced**: 64MB memory, 2 iterations, 2 threads (mid-range hardware)
- **Maximum**: 128MB memory, 4 iterations, 4 threads (high-end systems)

**Capability Detection:**
- Performance benchmarking during authentication
- Automatic profile selection based on hardware
- Minimum security thresholds enforced
- Reasonable authentication times maintained

## Session Management

### JWT Token System

**Token Architecture:**
- Short-lived access tokens (15-minute expiration)
- Long-lived refresh tokens (7-day expiration with rotation)
- Secure storage with HttpOnly, Secure, SameSite=Strict cookies
- Immediate token revocation support

**Session Security:**
- Stateless and scalable token validation
- Cryptographically independent from file encryption
- Session keys derived from OPAQUE authentication
- Distributed deployment support

### Access Control and Rate Limiting

**Authorization Enforcement:**
- Application-level access control
- Principle of least privilege
- User-specific file access only
- Comprehensive rate limiting across all endpoints

**Rate Limiting Features:**
- Adaptive thresholds based on device profiles
- Brute force attack prevention
- Account-based and IP-based limiting
- Graduated response to violation patterns

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
├── opaque/                # OPAQUE server keys (never rotated)
├── jwt/                   # JWT signing keys (rotatable)
└── backup/               # Encrypted key backups
```

**File Permissions:**
- Key directories: 700 permissions
- Private keys: 600 permissions
- Owned by arkfile user and group
- No world-readable access

**Key Rotation Procedures:**
```bash
# JWT key rotation (weekly)
./scripts/rotate-jwt-keys.sh

# Emergency rotation (immediate)
./scripts/rotate-jwt-keys.sh --force

# OPAQUE key backup (monthly)
./scripts/backup-keys.sh
```

### Authentication Security

**OPAQUE Protocol Security:**
- Registration flow with client-side Argon2ID
- OPAQUE blinding prevents password transmission
- Server-side hardening of stored envelopes
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

### Automated Alerting

**Alert Configuration:**
```bash
# Setup alert handler
cat > /opt/arkfile/scripts/security-alert.sh << 'EOF'
#!/bin/bash
ALERT_TYPE="$1"
MESSAGE="$2"

case "$ALERT_TYPE" in
    "critical")
        echo "$MESSAGE" | mail -s "CRITICAL: Arkfile Security Alert" admin@company.com
        curl -X POST "$SLACK_WEBHOOK" -d "{\"text\":\"CRITICAL: $MESSAGE\"}"
        ;;
    "warning")
        logger -p user.warning "Arkfile Security Warning: $MESSAGE"
        ;;
esac
EOF
```

**Monitoring Automation:**
```bash
# Add to crontab for automated monitoring
# Check for authentication failures every 15 minutes
*/15 * * * * /opt/arkfile/scripts/security-monitor.sh
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
./scripts/backup-keys.sh

# Capture logs
sudo journalctl -u arkfile --since "1 hour ago" > incident-logs.txt
```

**Assessment Phase:**
```bash
# Run security audit
./scripts/security-audit.sh

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
./scripts/rotate-jwt-keys.sh --force

# Revoke all active sessions
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/admin/revoke-all-sessions

# Enable enhanced monitoring
sudo systemctl edit arkfile
# Add: [Service] Environment="LOG_LEVEL=debug"
```

### Key Compromise Response

**CRITICAL: OPAQUE Server Key Compromise**

If OPAQUE server key compromise is suspected:

```bash
# WARNING: This invalidates ALL user accounts
# Only execute if absolutely certain of compromise

# 1. Immediate service shutdown
sudo systemctl stop arkfile

# 2. Backup everything
sudo tar -czf /opt/arkfile/backups/emergency-backup-$(date +%Y%m%d-%H%M%S).tar.gz \
  /opt/arkfile/var/lib /opt/arkfile/etc/keys

# 3. Generate new OPAQUE server key
./scripts/setup-opaque-keys.sh --force

# 4. Clear all user authentication data
rqlite -H localhost:4001 \
  "DELETE FROM opaque_registrations; DELETE FROM opaque_server_keys;"

# 5. Notify all users of required re-registration
echo "ALL USERS MUST RE-REGISTER - OPAQUE KEY ROTATED DUE TO SECURITY INCIDENT"
```

## Compliance and Auditing

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

### Compliance Frameworks

**SOC 2 Type II:**
- Continuous monitoring implementation
- Quarterly security assessments
- Annual penetration testing
- Vendor security assessments

**ISO 27001:**
- Risk assessment documentation
- Security policy implementation
- Regular security reviews
- Incident response procedures

**NIST Cybersecurity Framework:**
- Asset inventory maintenance
- Vulnerability management
- Access control implementation
- Security awareness training

### Regular Audit Procedures

**Weekly Tasks:**
```bash
# Security event review
./scripts/security-audit.sh

# Key health verification
./scripts/health-check.sh

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
./scripts/security-audit.sh --comprehensive

# Key backup verification
./scripts/backup-keys.sh --verify

# Performance security baseline
./scripts/performance-benchmark.sh
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
  "SELECT entity_id, count(DISTINCT user_email) as unique_users
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
  "SELECT user_email, count(*) as file_accesses
   FROM security_events 
   WHERE event_type='file_access'
   AND timestamp > datetime('now', '-1 hour')
   GROUP BY user_email
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
echo "=== Arkfile Security Metrics Report - $DATE ==="

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

## Emergency Contacts and Escalation

### Security Team Contacts
- **Security Operations**: security@company.com
- **Incident Response**: incidents@company.com
- **On-Call Security**: oncall-security@company.com

### Escalation Matrix
1. **Level 1**: System Administrator (Response: 30 minutes)
2. **Level 2**: Security Team Lead (Response: 2 hours)
3. **Level 3**: Security Director (Response: 4 hours)
4. **Level 4**: Executive Team (Response: 24 hours)

### External Resources
- **Legal Counsel**: legal@company.com
- **Public Relations**: pr@company.com
- **Regulatory Affairs**: compliance@company.com
- **Cyber Insurance**: insurance@company.com

---

## Quick Reference

### Critical Security Commands
```bash
# Emergency service stop
sudo systemctl stop arkfile

# Emergency key rotation
./scripts/rotate-jwt-keys.sh --force

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
- **Quantum Resistance**: Argon2ID memory-hard functions
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
