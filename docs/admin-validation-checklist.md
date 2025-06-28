# Administrative Validation Checklist for Arkfile

This checklist provides administrators with a comprehensive validation framework to ensure Arkfile is properly deployed, configured, and functional.

## Quick Start Validation

**For rapid deployment testing, run:**
```bash
./scripts/admin-integration-test.sh
```

This automated script provides step-by-step guidance through all validation phases.

## Manual Validation Checklist

### Phase 1: Environment and Services ✅

#### System Services
- [ ] **Arkfile service running**: `sudo systemctl status arkfile`
  - Expected: `Active: active (running)`
  - Troubleshoot: `sudo journalctl -u arkfile --no-pager -n 20`

- [ ] **MinIO service running**: `sudo systemctl status minio@node1`  
  - Expected: `Active: active (running)`
  - Troubleshoot: `sudo journalctl -u minio@node1 --no-pager -n 20`

- [ ] **Database ready**: rqlite service running
  - Check: `sudo systemctl status rqlite@node1`
  - Connectivity: `rqlite -H localhost:4001 'SELECT 1'`

#### Network Connectivity
- [ ] **Web interface accessible**: `curl -f http://localhost:8080/health`
  - Expected: HTTP 200 response or connection success
  - Troubleshoot: Check if port 8080 is available: `netstat -tlnp | grep 8080`

- [ ] **MinIO accessible**: `curl -f http://localhost:9000/minio/health/live`
  - Expected: HTTP 200 response 
  - Troubleshoot: Check MinIO logs and port availability

#### Configuration Files
- [ ] **Main configuration exists**: `/opt/arkfile/releases/current/.env`
  - Must contain: `PORT`, `MINIO_*`, `DATABASE_*` variables
  - Permissions: Readable by `arkfile` user, not world-readable

- [ ] **Directory structure**: 
  - [ ] `/opt/arkfile/var/lib/` exists with proper ownership
  - [ ] `/opt/arkfile/etc/keys/` exists with secure permissions (700)
  - [ ] `/opt/arkfile/var/log/` exists for logging

### Phase 2: Security and Cryptography ✅

#### Key Management
- [ ] **OPAQUE keys generated**: Check `/opt/arkfile/etc/keys/opaque/`
  - Must contain: `server_private_key.bin`
  - Permissions: 600, owned by `arkfile` user

- [ ] **JWT keys generated**: Check `/opt/arkfile/etc/keys/jwt/`
  - Must contain: `private_key.pem`, `public_key.pem`
  - Permissions: 600 for private, 644 for public

- [ ] **File encryption keys**: Dynamically generated per file
  - Verify through integration test file upload/download

#### Authentication System
- [ ] **OPAQUE protocol active**: Registration and login work
  - Test with: `admin@example.com` / `TestPassword123!`
  - Verify: No password hashes stored in database
  - Check: Session tokens are JWT format

- [ ] **Rate limiting functional**: 
  - Verify: Excessive login attempts are blocked
  - Check: Rate limiting headers in HTTP responses

### Phase 3: Core Functionality ✅

#### User Registration & Authentication
- [ ] **User registration works**:
  1. Navigate to: `http://localhost:8080`
  2. Click "Register"
  3. Enter: `admin@example.com` / `TestPassword123!`
  4. Expected: Success message, redirect to dashboard

- [ ] **User login works**:
  1. Log out from current session
  2. Login with same credentials
  3. Expected: Access to dashboard, files visible

- [ ] **Session persistence**:
  - Files remain accessible across browser sessions
  - JWT tokens properly validated
  - Session expiry works as configured

#### File Operations
- [ ] **File upload functional**:
  1. Create test file: `echo "Hello World" > test.txt`
  2. Upload via web interface
  3. Expected: File appears in list with encryption icon
  4. Verify: File stored encrypted in MinIO

- [ ] **File download functional**:
  1. Click on uploaded file name
  2. File downloads automatically
  3. Expected: Content matches original exactly
  4. Verify: File is decrypted properly

- [ ] **File encryption verified**:
  - Check: Files in MinIO storage are encrypted (unreadable)
  - Verify: Each file has unique encryption key
  - Confirm: Header bytes 0x04/0x05 present in encrypted files

#### File Sharing
- [ ] **Share generation works**:
  1. Click "Share" next to uploaded file
  2. Share link is generated
  3. Expected: URL format includes share token

- [ ] **Anonymous access works**:
  1. Copy share link
  2. Open incognito/private browser window
  3. Paste share link
  4. Expected: File downloads without login
  5. Verify: Content matches original

### Phase 4: Performance and Monitoring ✅

#### Performance Validation
- [ ] **Response times acceptable**:
  - Registration: < 2 seconds
  - Login: < 1 second  
  - File upload (1KB): < 1 second
  - File download (1KB): < 1 second
  - Share generation: < 500ms

- [ ] **Memory usage reasonable**:
  - Check: `ps aux | grep arkfile` shows normal memory usage
  - Verify: No memory leaks during extended testing

#### Logging and Monitoring
- [ ] **Application logs accessible**:
  - View: `sudo journalctl -u arkfile -f`
  - Expected: Clean startup messages, no errors
  - Verify: Security events logged appropriately

- [ ] **Health endpoints functional**:
  - Check: `curl http://localhost:8080/health`
  - Expected: JSON response with system status
  - Verify: Database and storage connectivity reported

### Phase 5: Security Validation ✅

#### Security Features Active
- [ ] **OPAQUE authentication verified**:
  - No password hashes in database
  - Registration uses OPAQUE protocol
  - Login provides mutual authentication

- [ ] **Encryption parameters correct**:
  - Algorithm: AES-GCM
  - Key size: 256 bits
  - Unique keys per file confirmed

- [ ] **Rate limiting active**:
  - Excessive requests blocked
  - IP-based and account-based limits enforced
  - Proper HTTP status codes returned (429)

#### Security Audit
- [ ] **Run security audit**: `./scripts/security-audit.sh`
  - Expected: No critical security issues
  - Review: Any warnings and recommendations
  - Verify: All checks pass or have documented exceptions

## Troubleshooting Common Issues

### Service Not Starting
**Symptoms**: `systemctl status arkfile` shows failed state

**Troubleshooting**:
1. Check logs: `sudo journalctl -u arkfile --no-pager -n 50`
2. Verify configuration: `cat /opt/arkfile/releases/current/.env`
3. Check database permissions: `ls -la /opt/arkfile/var/lib/dev/`
4. Verify MinIO connectivity: `sudo systemctl status minio@node1`

### Web Interface Not Accessible
**Symptoms**: Browser shows "connection refused" or timeout

**Troubleshooting**:
1. Check if service is running: `sudo systemctl status arkfile`
2. Verify port availability: `netstat -tlnp | grep 8080`
3. Check firewall: `sudo ufw status` (if applicable)
4. Review bind address in configuration

### Authentication Failures
**Symptoms**: Login attempts fail with "invalid credentials"

**Troubleshooting**:
1. Check OPAQUE key generation: `ls -la /opt/arkfile/etc/keys/opaque/`
2. Verify database connectivity and permissions
3. Check for rate limiting: Look for 429 HTTP responses
4. Review application logs for authentication errors

### File Upload/Download Issues
**Symptoms**: Files fail to upload or download incorrectly

**Troubleshooting**:
1. Check MinIO service: `sudo systemctl status minio@node1`
2. Verify MinIO connectivity from application
3. Check file permissions in storage directories
4. Review encryption key generation logs

## Production Deployment Notes

### For Production Use
- **Database**: Use `./scripts/setup-rqlite.sh` (without --dev flag)
- **TLS**: Enable with `./scripts/setup-tls-certs.sh`
- **Security**: Run `./scripts/security-audit.sh` regularly
- **Monitoring**: Set up log aggregation and alerting
- **Backups**: Implement automated backup procedures

### Regular Maintenance
- **Key Rotation**: Use `./scripts/rotate-jwt-keys.sh` periodically
- **Health Checks**: Monitor with `./scripts/health-check.sh`
- **Performance**: Run `./scripts/performance-benchmark.sh` regularly
- **Security**: Execute `./scripts/security-audit.sh` monthly

## Success Criteria Summary

✅ **Environment**: All services running, configuration valid
✅ **Security**: OPAQUE authentication active, encryption verified  
✅ **Functionality**: Registration, login, file operations work
✅ **Performance**: Response times within acceptable ranges
✅ **Monitoring**: Logging functional, health checks passing

**System is ready for use when all checklist items are verified ✅**

---

*For automated validation, use: `./scripts/admin-integration-test.sh`*
*For ongoing monitoring, use: `./scripts/health-check.sh`*
