# Arkfile Security Operations Guide

This guide provides comprehensive security procedures and operational guidance for maintaining enterprise-grade security in Arkfile deployments.

## Table of Contents

1. [Security Architecture Overview](#security-architecture-overview)
2. [Cryptographic Key Management](#cryptographic-key-management)
3. [Authentication Security](#authentication-security)
4. [Monitoring and Alerting](#monitoring-and-alerting)
5. [Incident Response](#incident-response)
6. [Compliance and Auditing](#compliance-and-auditing)
7. [Security Hardening](#security-hardening)
8. [Threat Detection](#threat-detection)

## Security Architecture Overview

### Defense in Depth

Arkfile implements multiple layers of security:

1. **Transport Layer**: TLS 1.3 encryption for all communications
2. **Authentication**: OPAQUE password-authenticated key exchange (PAKE)
3. **File Encryption**: AES-256-GCM with independent key derivation
4. **Key Management**: Hardware security module (HSM) ready architecture
5. **Access Control**: Role-based access with JWT token validation
6. **Audit Logging**: Comprehensive security event tracking

### Cryptographic Domain Separation

```
┌─────────────────────────────────────────────────────────────┐
│                    ARKFILE SECURITY DOMAINS                 │
├─────────────────────────────────────────────────────────────┤
│  Authentication Domain (OPAQUE)                            │
│  ├── OPAQUE Server Private Key                             │
│  ├── User Authentication Envelopes                         │
│  └── Session Key Derivation                                │
├─────────────────────────────────────────────────────────────┤
│  File Encryption Domain (Independent)                      │
│  ├── User-derived File Encryption Keys                     │
│  ├── AES-GCM Encrypted File Content                        │
│  └── Multi-key Envelope Support                            │
├─────────────────────────────────────────────────────────────┤
│  JWT Token Domain                                          │
│  ├── JWT Signing Keys (Rotatable)                          │
│  ├── Access Tokens                                         │
│  └── Refresh Tokens                                        │
└─────────────────────────────────────────────────────────────┘
```

### Security Properties

- **No Cross-Domain Key Derivation**: Authentication keys never influence file encryption
- **Forward Secrecy**: Compromised long-term keys don't affect past sessions
- **Quantum Resistance**: Argon2ID provides protection against quantum attacks
- **ASIC Resistance**: Memory-hard functions prevent specialized hardware attacks

## Cryptographic Key Management

### Key Hierarchy

```
Root Security
├── OPAQUE Server Private Key (Long-term, stable)
│   ├── Per-user authentication state
│   └── Session key derivation
├── JWT Signing Keys (Rotatable)
│   ├── Access token validation
│   └── Refresh token validation  
└── File Encryption Keys (User-derived)
    ├── Password-based key derivation
    └── Multi-key envelope support
```

### Key Storage Security

#### Directory Structure
```bash
/etc/arkfile/keys/
├── opaque_server.key     # OPAQUE server private key (never rotated)
├── jwt_signing.key       # Current JWT signing key
├── jwt_signing.key.old   # Previous JWT signing key (rotation grace period)
└── backup/               # Encrypted key backups
    ├── opaque_backup_YYYYMMDD.enc
    └── jwt_backup_YYYYMMDD.enc
```

#### File Permissions
```bash
# Key directory permissions
drwx------ 2 arkfile arkfile 4096 /etc/arkfile/keys/

# Individual key file permissions  
-rw------- 1 arkfile arkfile  256 opaque_server.key
-rw------- 1 arkfile arkfile  256 jwt_signing.key
```

### Key Rotation Procedures

#### JWT Key Rotation (Weekly)

```bash
# Automated rotation (recommended)
sudo systemctl enable arkfile-key-rotation.timer
sudo systemctl start arkfile-key-rotation.timer

# Manual rotation
sudo -u arkfile /opt/arkfile/src/scripts/rotate-jwt-keys.sh

# Emergency rotation (immediate)
sudo -u arkfile /opt/arkfile/src/scripts/rotate-jwt-keys.sh --force
```

#### OPAQUE Key Stability

**CRITICAL**: OPAQUE server keys must NEVER be rotated as this would invalidate all user accounts.

```bash
# Backup OPAQUE key (recommended monthly)
sudo -u arkfile /opt/arkfile/src/scripts/backup-keys.sh

# Verify OPAQUE key integrity
sudo -u arkfile openssl rand -hex 32 | \
  openssl dgst -sha256 -hmac "$(cat /etc/arkfile/keys/opaque_server.key)"
```

### Hardware Security Module (HSM) Integration

For high-security deployments, integrate with HSM:

```yaml
# config.yaml
key_management:
  hsm_enabled: true
  hsm_provider: "pkcs11"
  hsm_config:
    library_path: "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so"
    slot_id: 0
    pin_source: "env:HSM_PIN"
```

## Authentication Security

### OPAQUE Protocol Security

#### Registration Flow Security
1. **Client-side Argon2ID**: Adaptive parameters based on device capability
2. **OPAQUE Blinding**: Password never transmitted in clear
3. **Server-side Hardening**: Additional Argon2ID applied to envelopes
4. **Database Storage**: Only hardened envelopes stored, never passwords

#### Login Flow Security
1. **Mutual Authentication**: Both client and server prove authenticity
2. **Key Exchange**: Secure session key establishment
3. **Replay Protection**: Nonce-based challenge/response
4. **Brute Force Protection**: Progressive penalties and rate limiting

### Device Profile Security

```go
// Argon2ID Device Profiles
var DeviceProfiles = map[string]ArgonParams{
    "minimal":     {Memory: 32 * 1024, Time: 1, Threads: 2},  // 32MB, mobile
    "interactive": {Memory: 32 * 1024, Time: 1, Threads: 2},  // 32MB, responsive
    "balanced":    {Memory: 64 * 1024, Time: 2, Threads: 2},  // 64MB, balanced
    "maximum":     {Memory: 128 * 1024, Time: 4, Threads: 4}, // 128MB, secure
}
```

### Session Management

#### JWT Token Security
- **Short-lived Access Tokens**: 15-minute expiration
- **Long-lived Refresh Tokens**: 7-day expiration with rotation
- **Secure Storage**: HttpOnly, Secure, SameSite=Strict cookies
- **Token Revocation**: Immediate invalidation support

#### Session Validation
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

#### Critical Events (Immediate Response Required)
- Multiple authentication failures from single IP
- Suspicious access patterns
- Key file modifications
- Emergency procedure activations
- Database integrity failures

#### Warning Events (Review Within Hours)
- Rate limit violations
- JWT refresh failures
- Configuration changes
- Unusual file access patterns

#### Info Events (Daily Review)
- Successful authentications
- Key health checks
- System startup/shutdown
- Routine maintenance operations

### Log Analysis

#### Security Event Query Examples

```bash
# View recent critical events
sudo -u arkfile sqlite3 /opt/arkfile/data/arkfile.db \
  "SELECT * FROM security_events WHERE severity='CRITICAL' 
   AND timestamp > datetime('now', '-24 hours') 
   ORDER BY timestamp DESC;"

# Analyze authentication patterns by entity
sudo -u arkfile sqlite3 /opt/arkfile/data/arkfile.db \
  "SELECT entity_id, count(*) as attempts, 
          sum(case when details like '%success%' then 1 else 0 end) as successes
   FROM security_events 
   WHERE event_type LIKE '%login%' 
   AND time_window = date('now')
   GROUP BY entity_id 
   HAVING attempts > 10;"

# Monitor rate limiting effectiveness
sudo -u arkfile sqlite3 /opt/arkfile/data/arkfile.db \
  "SELECT time_window, count(*) as violations
   FROM security_events 
   WHERE event_type = 'rate_limit_violation'
   GROUP BY time_window 
   ORDER BY time_window DESC 
   LIMIT 7;"
```

### Automated Alerting

#### Setup Alert Scripts

```bash
# Create alert handler
cat > /opt/arkfile/scripts/security-alert.sh << 'EOF'
#!/bin/bash
ALERT_TYPE="$1"
MESSAGE="$2"
DETAILS="$3"

case "$ALERT_TYPE" in
    "critical")
        # Send immediate notification
        echo "$MESSAGE" | mail -s "CRITICAL: Arkfile Security Alert" admin@company.com
        # Trigger PagerDuty/Slack webhook
        curl -X POST "$SLACK_WEBHOOK" -d "{\"text\":\"CRITICAL: $MESSAGE\"}"
        ;;
    "warning")
        # Log for review
        logger -p user.warning "Arkfile Security Warning: $MESSAGE"
        ;;
esac
EOF

chmod +x /opt/arkfile/scripts/security-alert.sh
```

#### Monitor Critical Patterns

```bash
# Add to crontab for automated monitoring
cat > /opt/arkfile/scripts/security-monitor.sh << 'EOF'
#!/bin/bash
DB="/opt/arkfile/data/arkfile.db"

# Check for multiple failures from same entity
FAILURES=$(sqlite3 "$DB" "
  SELECT entity_id, count(*) 
  FROM security_events 
  WHERE event_type='opaque_login_failure' 
  AND timestamp > datetime('now', '-1 hour')
  GROUP BY entity_id 
  HAVING count(*) >= 5
")

if [ -n "$FAILURES" ]; then
    /opt/arkfile/scripts/security-alert.sh "critical" \
      "Multiple authentication failures detected" "$FAILURES"
fi

# Check for key file modifications
MODIFIED=$(find /etc/arkfile/keys -newer /tmp/arkfile-last-check 2>/dev/null)
if [ -n "$MODIFIED" ]; then
    /opt/arkfile/scripts/security-alert.sh "critical" \
      "Key files modified: $MODIFIED"
fi

touch /tmp/arkfile-last-check
EOF

# Run every 15 minutes
echo "*/15 * * * * /opt/arkfile/scripts/security-monitor.sh" | crontab -
```

## Incident Response

### Security Incident Classification

#### Severity 1 - Critical (Immediate Response)
- Key compromise suspected
- Active brute force attack
- Database integrity failure
- Authentication bypass detected

#### Severity 2 - High (Response within 2 hours)
- Suspicious access patterns
- Rate limiting failures
- Configuration tampering
- Service availability issues

#### Severity 3 - Medium (Response within 24 hours)
- Policy violations
- Unusual usage patterns
- Performance degradation
- Audit compliance issues

### Incident Response Procedures

#### Emergency Response Playbook

1. **Immediate Actions**
   ```bash
   # Stop service if compromise suspected
   sudo systemctl stop arkfile
   
   # Backup current state
   sudo -u arkfile /opt/arkfile/src/scripts/backup-keys.sh
   
   # Capture logs
   sudo journalctl -u arkfile --since "1 hour ago" > incident-logs.txt
   ```

2. **Assessment Phase**
   ```bash
   # Run security audit
   sudo -u arkfile /opt/arkfile/src/scripts/security-audit.sh
   
   # Check file integrity
   sudo -u arkfile find /etc/arkfile -type f -exec sha256sum {} \; > file-hashes.txt
   
   # Analyze recent security events
   sudo -u arkfile sqlite3 /opt/arkfile/data/arkfile.db \
     "SELECT * FROM security_events 
      WHERE timestamp > datetime('now', '-24 hours') 
      ORDER BY severity DESC, timestamp DESC;"
   ```

3. **Containment Actions**
   ```bash
   # Rotate JWT keys immediately
   sudo -u arkfile /opt/arkfile/src/scripts/rotate-jwt-keys.sh --force
   
   # Revoke all active sessions
   curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
     http://localhost:8080/admin/revoke-all-sessions
   
   # Enable enhanced monitoring
   sudo systemctl edit arkfile
   # Add: [Service] Environment="LOG_LEVEL=debug"
   ```

#### Key Compromise Response

**If OPAQUE server key compromise is suspected:**

```bash
# CRITICAL: This invalidates ALL user accounts
# Only execute if absolutely certain of compromise

# 1. Immediate service shutdown
sudo systemctl stop arkfile

# 2. Backup everything
sudo tar -czf /opt/arkfile/backups/emergency-backup-$(date +%Y%m%d-%H%M%S).tar.gz \
  /opt/arkfile/data /etc/arkfile

# 3. Generate new OPAQUE server key
sudo -u arkfile /opt/arkfile/src/scripts/setup-opaque-keys.sh --force

# 4. Clear all user authentication data
sudo -u arkfile sqlite3 /opt/arkfile/data/arkfile.db \
  "DELETE FROM opaque_registrations; DELETE FROM opaque_server_keys;"

# 5. Notify all users of required re-registration
echo "ALL USERS MUST RE-REGISTER - OPAQUE KEY ROTATED DUE TO SECURITY INCIDENT" | \
  tee /opt/arkfile/data/security-notice.txt
```

### Forensics and Evidence Collection

#### Log Preservation
```bash
# Preserve logs for forensic analysis
sudo mkdir -p /opt/arkfile/forensics/$(date +%Y%m%d-%H%M%S)
sudo cp -r /var/log/arkfile /opt/arkfile/forensics/$(date +%Y%m%d-%H%M%S)/
sudo journalctl -u arkfile --since "7 days ago" > \
  /opt/arkfile/forensics/$(date +%Y%m%d-%H%M%S)/systemd-logs.txt
```

#### Database Analysis
```bash
# Export security events for analysis
sudo -u arkfile sqlite3 /opt/arkfile/data/arkfile.db \
  ".headers on" \
  ".mode csv" \
  ".output /opt/arkfile/forensics/security-events.csv" \
  "SELECT * FROM security_events WHERE timestamp > datetime('now', '-30 days');"
```

## Compliance and Auditing

### Audit Trail Requirements

#### Required Audit Events
- All authentication attempts (success/failure)
- Key management operations
- Administrative actions
- Configuration changes
- Emergency procedures
- Data access patterns

#### Audit Log Retention
- **Security Events**: 90 days minimum
- **Authentication Logs**: 1 year
- **Key Management**: 7 years
- **Emergency Procedures**: Permanent

### Compliance Frameworks

#### SOC 2 Type II
- Implement continuous monitoring
- Quarterly security assessments
- Annual penetration testing
- Vendor security assessments

#### ISO 27001
- Risk assessment documentation
- Security policy implementation
- Regular security reviews
- Incident response procedures

#### NIST Cybersecurity Framework
- Asset inventory maintenance
- Vulnerability management
- Access control implementation
- Security awareness training

### Regular Audit Procedures

#### Weekly Audit Tasks
```bash
# Security event review
sudo -u arkfile /opt/arkfile/src/scripts/security-audit.sh

# Key health verification
sudo -u arkfile /opt/arkfile/src/scripts/health-check.sh

# Authentication pattern analysis
sudo -u arkfile sqlite3 /opt/arkfile/data/arkfile.db \
  "SELECT date(timestamp) as day, 
          count(*) as total_attempts,
          sum(case when event_type='opaque_login_success' then 1 else 0 end) as successes
   FROM security_events 
   WHERE timestamp > datetime('now', '-7 days')
   GROUP BY date(timestamp)
   ORDER BY day DESC;"
```

#### Monthly Audit Tasks
```bash
# Comprehensive security assessment
sudo -u arkfile /opt/arkfile/src/scripts/security-audit.sh --comprehensive

# Key backup verification
sudo -u arkfile /opt/arkfile/src/scripts/backup-keys.sh --verify

# Performance security baseline
sudo -u arkfile /opt/arkfile/src/scripts/performance-benchmark.sh

# Golden test format validation
sudo -u arkfile /opt/arkfile/src/scripts/golden-test-preservation.sh --validate
```

## Security Hardening

### System-Level Hardening

#### File System Security
```bash
# Mount options for key directories
echo "/etc/arkfile /etc/arkfile ext4 defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab

# Secure temporary directories
echo "tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec,size=1G 0 0" >> /etc/fstab

# Enable file system integrity monitoring
apt install -y aide
aide --init
aide --check
```

#### Network Security
```bash
# Configure iptables rules
iptables -A INPUT -p tcp --dport 8080 -m conntrack --ctstate NEW -m limit --limit 60/min -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP

# Enable fail2ban for SSH protection
apt install -y fail2ban
systemctl enable fail2ban
systemctl start fail2ban
```

#### Process Security
```bash
# Enable address space layout randomization
echo 2 > /proc/sys/kernel/randomize_va_space

# Disable core dumps for security
echo "* hard core 0" >> /etc/security/limits.conf

# Set process limits
echo "arkfile soft nproc 4096" >> /etc/security/limits.conf
echo "arkfile hard nproc 8192" >> /etc/security/limits.conf
```

### Application-Level Hardening

#### Memory Protection
```go
// Enable in Go build
// go build -ldflags="-s -w" -buildmode=pie arkfile
```

#### Compiler Security Features
```bash
# Build with security flags
export CGO_CFLAGS="-fstack-protector-strong -D_FORTIFY_SOURCE=2"
export CGO_LDFLAGS="-Wl,-z,relro,-z,now"
go build -buildmode=pie -ldflags="-s -w" .
```

### Container Security (Optional)

#### Docker Hardening
```dockerfile
# Use minimal base image
FROM gcr.io/distroless/static:nonroot

# Non-root user
USER 65534:65534

# Read-only filesystem
VOLUME ["/etc/arkfile/keys"]
VOLUME ["/opt/arkfile/data"]

# Security options
LABEL security.capability="none"
LABEL security.no-new-privileges="true"
```

## Threat Detection

### Attack Pattern Recognition

#### Brute Force Detection
```bash
# Monitor authentication failure patterns
sudo -u arkfile sqlite3 /opt/arkfile/data/arkfile.db \
  "SELECT entity_id, 
          count(*) as failures,
          min(timestamp) as first_attempt,
          max(timestamp) as last_attempt
   FROM security_events 
   WHERE event_type='opaque_login_failure'
   AND timestamp > datetime('now', '-24 hours')
   GROUP BY entity_id
   HAVING count(*) > 10
   ORDER BY count(*) DESC;"
```

#### Credential Stuffing Detection
```bash
# Detect rapid authentication attempts across multiple accounts
sudo -u arkfile sqlite3 /opt/arkfile/data/arkfile.db \
  "SELECT entity_id,
          count(DISTINCT user_email) as unique_users,
          count(*) as total_attempts
   FROM security_events 
   WHERE event_type IN ('opaque_login_failure', 'opaque_login_success')
   AND timestamp > datetime('now', '-1 hour')
   GROUP BY entity_id
   HAVING unique_users > 5 AND total_attempts > 20;"
```

#### Suspicious Access Patterns
```bash
# Identify unusual file access patterns
sudo -u arkfile sqlite3 /opt/arkfile/data/arkfile.db \
  "SELECT user_email,
          count(*) as file_accesses,
          count(DISTINCT details) as unique_files
   FROM security_events 
   WHERE event_type='file_access'
   AND timestamp > datetime('now', '-1 hour')
   GROUP BY user_email
   HAVING file_accesses > 100 OR unique_files > 50;"
```

### Automated Threat Response

#### Rate Limiting Enhancement
```bash
# Dynamic rate limiting based on threat level
cat > /opt/arkfile/scripts/adaptive-rate-limit.sh << 'EOF'
#!/bin/bash
DB="/opt/arkfile/data/arkfile.db"
CURRENT_HOUR=$(date +"%H")

# Check threat level
THREAT_LEVEL=$(sqlite3 "$DB" "
  SELECT CASE 
    WHEN count(*) > 100 THEN 'HIGH'
    WHEN count(*) > 50 THEN 'MEDIUM'
    ELSE 'LOW'
  END
  FROM security_events 
  WHERE event_type='rate_limit_violation'
  AND timestamp > datetime('now', '-1 hour')
")

# Adjust rate limits based on threat level
case "$THREAT_LEVEL" in
    "HIGH")
        # Aggressive rate limiting
        curl -X POST http://localhost:8080/admin/rate-limit \
          -d '{"requests_per_hour": 10, "burst": 5}'
        ;;
    "MEDIUM")
        # Enhanced rate limiting
        curl -X POST http://localhost:8080/admin/rate-limit \
          -d '{"requests_per_hour": 50, "burst": 10}'
        ;;
    "LOW")
        # Normal rate limiting
        curl -X POST http://localhost:8080/admin/rate-limit \
          -d '{"requests_per_hour": 100, "burst": 20}'
        ;;
esac
EOF
```

#### IP Blocking Automation
```bash
# Automatic IP blocking for severe violations
cat > /opt/arkfile/scripts/auto-block-ips.sh << 'EOF'
#!/bin/bash
DB="/opt/arkfile/data/arkfile.db"

# Find IPs with excessive failures (would need IP logging enabled)
MALICIOUS_IPS=$(sqlite3 "$DB" "
  SELECT entity_id
  FROM security_events 
  WHERE event_type='opaque_login_failure'
  AND timestamp > datetime('now', '-1 hour')
  GROUP BY entity_id
  HAVING count(*) > 50
")

# Block malicious IPs (if IP correlation available)
for ip in $MALICIOUS_IPS; do
    # This would require mapping entity_id back to IP
    # iptables -A INPUT -s "$ip" -j DROP
    logger "Would block entity: $ip for excessive failures"
done
EOF
```

### Security Metrics and KPIs

#### Key Performance Indicators
- **Authentication Success Rate**: >95%
- **Average Response Time**: <500ms
- **False Positive Rate**: <1%
- **Mean Time to Detection**: <15 minutes
- **Mean Time to Response**: <2 hours

#### Security Dashboards
```bash
# Generate security metrics report
cat > /opt/arkfile/scripts/security-metrics.sh << 'EOF'
#!/bin/bash
DB="/opt/arkfile/data/arkfile.db"
DATE=$(date +"%Y-%m-%d")

echo "=== Arkfile Security Metrics Report - $DATE ==="
echo

# Authentication metrics
echo "Authentication Metrics (Last 24 hours):"
sqlite3 "$DB" "
  SELECT 
    'Total Attempts: ' || count(*),
    'Successful: ' || sum(case when event_type='opaque_login_success' then 1 else 0 end),
    'Failed: ' || sum(case when event_type='opaque_login_failure' then 1 else 0 end),
    'Success Rate: ' || printf('%.2f%%', 
      100.0 * sum(case when event_type='opaque_login_success' then 1 else 0 end) / count(*)
    )
  FROM security_events 
  WHERE event_type IN ('opaque_login_success', 'opaque_login_failure')
  AND timestamp > datetime('now', '-24 hours');
"

echo
echo "Rate Limiting Metrics (Last 24 hours):"
sqlite3 "$DB" "
  SELECT 
    'Rate Limit Violations: ' || count(*)
  FROM security_events 
  WHERE event_type='rate_limit_violation'
  AND timestamp > datetime('now', '-24 hours');
"

echo
echo "Top Security Events (Last 7 days):"
sqlite3 "$DB" "
  SELECT event_type, count(*) as occurrences
  FROM security_events 
  WHERE timestamp > datetime('now', '-7 days')
  GROUP BY event_type
  ORDER BY count(*) DESC
  LIMIT 10;
"
EOF

chmod +x /opt/arkfile/scripts/security-metrics.sh
```

---

## Emergency Contacts and Escalation

### Security Team Contacts
- **Security Operations Center**: +1-XXX-XXX-XXXX
- **Incident Response Team**: security-incidents@company.com
- **On-Call Security Engineer**: oncall-security@company.com

### Escalation Matrix
1. **Level 1**: System Administrator (Response: 30 minutes)
2. **Level 2**: Security Team Lead (Response: 2 hours)
3. **Level 3**: CISO/Security Director (Response: 4 hours)
4. **Level 4**: Executive Team (Response: 24 hours)

### External Resources
- **Legal Counsel**: legal@company.com
- **Public Relations**: pr@company.com
- **Regulatory Affairs**: compliance@company.com
- **Cyber Insurance**: insurance-claims@company.com

---

## Quick Reference

### Critical Commands
```bash
# Emergency service stop
sudo systemctl stop arkfile

# Emergency key rotation
sudo -u arkfile /opt/arkfile/src/scripts/rotate-jwt-keys.sh --force

# Security audit
sudo -u arkfile /opt/arkfile/src/scripts/security-audit.sh

# Health check
curl http://localhost:8080/health

# View recent critical events
sudo -u arkfile sqlite3 /opt/arkfile/data/arkfile.db \
  "SELECT * FROM security_events WHERE severity='CRITICAL' 
   AND timestamp > datetime('now', '-1 hour');"
```

### Log Locations
- **Application Logs**: `/var/log/arkfile/app.log`
- **Security Events**: Database table `security_events`
- **System Logs**: `journalctl -u arkfile`
- **Audit Logs**: `/var/log/arkfile/audit.log`

This guide should be reviewed quarterly and updated based on emerging threats and operational experience.
