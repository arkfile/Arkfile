# Arkfile Admin Integration Testing Guide

This guide provides step-by-step instructions for administrators to validate that Arkfile is working correctly after deployment, with special attention to TLS certificate behavior and real-world user workflows.

## Table of Contents

1. [Understanding Your TLS Setup](#understanding-your-tls-setup)
2. [Post-Deployment Validation Steps](#post-deployment-validation-steps)
3. [Real-World User Flow Testing](#real-world-user-flow-testing)
4. [Backend Verification](#backend-verification)
5. [Troubleshooting Common Issues](#troubleshooting-common-issues)

## Understanding Your TLS Setup

### What Gets Configured Automatically

When you run `./scripts/integration-test.sh` with `COMPLETE` mode, the system creates:

1. **Self-signed CA certificate** for internal service communication
2. **Self-signed server certificate** for HTTPS web access
3. **Caddy reverse proxy** configuration (port 80/443 → port 8080)
4. **Internal service TLS** (MinIO ↔ rqlite ↔ Arkfile encrypted communication)

### Expected Access URLs After Complete Setup

#### HTTP Access (No Certificate Warnings)
- **Direct Arkfile**: `http://localhost:8080`
- **Through Caddy**: `http://localhost` (port 80)

#### HTTPS Access (With Self-Signed Certificates)
- **Through Caddy**: `https://localhost` (port 443)
- **Custom internal domain**: `https://arkfile.local` (if configured)

### Browser Certificate Warnings (NORMAL BEHAVIOR)

⚠️ **IMPORTANT**: When accessing `https://localhost` with self-signed certificates, you WILL see browser warnings. This is **EXPECTED and NORMAL** for development/internal deployments.

#### Chrome/Chromium
```
⚠️  "Your connection is not private"
NET::ERR_CERT_AUTHORITY_INVALID
```
**Action**: Click "Advanced" → "Proceed to localhost (unsafe)"

#### Firefox
```
⚠️  "Warning: Potential Security Risk Ahead"
```
**Action**: Click "Advanced..." → "Accept the Risk and Continue"

#### Safari
```
⚠️  "This Connection Is Not Private"
```
**Action**: Click "Show Details" → "visit this website"

#### Microsoft Edge
```
⚠️  "Your connection isn't private"
```
**Action**: Click "Advanced" → "Continue to localhost (unsafe)"

### Why Self-Signed Certificates Are Secure for Internal Use

1. **End-to-End Encryption**: All traffic is encrypted between browser and server
2. **OPAQUE Protocol Security**: Authentication security is independent of TLS certificates
3. **Internal Network**: Certificates are valid for your localhost/internal network
4. **Production Upgrade Path**: Easy to replace with Let's Encrypt or commercial certificates

## Post-Deployment Validation Steps

### 🎯 IMMEDIATE STEPS AFTER COMPLETE SETUP

**After running `./scripts/integration-test.sh` with `COMPLETE` mode, follow these exact steps:**

#### Step 0: Wait for Services to Start
```bash
# Services need 30-60 seconds to fully initialize
sleep 60

# Quick verification all services are ready
./scripts/health-check.sh --quick
```

#### Step 1: Choose Your Testing Approach

**📝 RECOMMENDED: Start with HTTP for validation**
- URL: `http://localhost:8080` 
- No certificate warnings
- Same OPAQUE security
- Easier for initial testing

**🔒 PRODUCTION-LIKE: Use HTTPS with certificate acceptance**
- URL: `https://localhost`
- Accept certificate warnings (normal for self-signed)
- Full TLS stack testing

### Step 1: Verify System Health

```bash
# Check overall system health
curl -s http://localhost:8080/health | jq '.'

# Expected response:
{
  "status": "healthy",
  "timestamp": "2025-06-27T22:30:00Z",
  "checks": {
    "database": {"status": "healthy"},
    "keys": {"status": "healthy"},
    "storage": {"status": "healthy"},
    "opaque": {"status": "healthy"}
  }
}
```

### Step 2: Verify Service Status

```bash
# Check all services are running
sudo systemctl status arkfile
sudo systemctl status caddy
sudo systemctl status minio@arkfile
sudo systemctl status rqlite@arkfile

# All should show: "Active: active (running)"
```

### Step 3: Test Network Connectivity

```bash
# Test HTTP access (no certificate warnings)
curl -I http://localhost:8080/
# Expected: HTTP/1.1 200 OK

# Test HTTPS access through Caddy (ignore certificate for testing)
curl -I https://localhost --insecure
# Expected: HTTP/2 200 OK
```

## Real-World User Flow Testing

### Phase A: Choose Your Testing Method

**Option 1: HTTP Testing (Recommended for validation)**
- URL: `http://localhost:8080`
- No certificate warnings
- Same security for OPAQUE authentication
- Faster for testing workflow

**Option 2: HTTPS Testing (Production-like)**
- URL: `https://localhost`
- Certificate warnings expected (accept them)
- Full production TLS stack
- Tests complete certificate chain

### Phase B: Web Interface Access Test

1. **Open browser** to your chosen URL
2. **Verify page loads** with "Secure File Sharing" title
3. **Check browser console** (F12 → Console) for JavaScript errors
   - Should be clean with no red errors
   - OPAQUE WebAssembly should load successfully

### Phase C: User Registration Test (OPAQUE Protocol)

1. **Click "Register"** on the web interface
2. **Enter test credentials**:
   - Email: `admin@test.local`
   - Password: `AdminTest123!@#` (or your preferred strong password)
3. **Verify password requirements** are checked in real-time
4. **Click "Register"**
5. **Expected result**: "Registration successful" message

#### Backend Verification
```bash
# Verify OPAQUE registration in database
sqlite3 /opt/arkfile/var/lib/database/arkfile.db \
  "SELECT email, created_at FROM users WHERE email='admin@test.local';"

# Should show: admin@test.local|2025-06-27 22:30:00
```

### Phase D: User Login Test (OPAQUE Authentication)

1. **Use the same credentials** from registration
2. **Click "Login"**
3. **Expected result**: Redirect to file upload interface
4. **Verify session establishment**: Page should show user controls (logout button, etc.)

#### Backend Verification
```bash
# Check OPAQUE authentication in logs
sudo journalctl -u arkfile --since="1 minute ago" | grep -i opaque
# Should show: OPAQUE authentication successful for user [entity_id]
```

### Phase E: File Upload & Encryption Test

1. **Create a test file**:
   ```bash
   echo "Hello Arkfile! This is a test file for encryption validation." > ~/test-file.txt
   ```

2. **Upload the file**:
   - Click "Choose File" and select `test-file.txt`
   - Select "Use my account password" (recommended)
   - Add optional password hint: "Test file for validation"
   - Click "Upload"

3. **Expected result**: 
   - Progress bar completes
   - File appears in "Your Files" section
   - File shows as encrypted (🔒 icon)

#### Backend Verification
```bash
# Check encrypted file in storage
ls -la /opt/arkfile/var/lib/storage/
# Should show encrypted file with .enc extension

# Verify file encryption headers
xxd -l 32 /opt/arkfile/var/lib/storage/[file-id].enc
# Should start with: 0x04 or 0x05 (Arkfile encryption headers)
```

### Phase F: File Download & Decryption Test

1. **Click download** on your uploaded file
2. **Enter your account password** when prompted
3. **Expected result**: File downloads and decrypts to original content

#### Verification
```bash
# Compare downloaded file with original
diff ~/test-file.txt ~/Downloads/test-file.txt
# Should show no differences (files identical)
```

### Phase G: File Sharing Test

1. **Click "Share"** on your uploaded file
2. **Copy the generated share link**
3. **Open incognito/private browser window**
4. **Visit the share link**
5. **Enter the file password** when prompted
6. **Expected result**: File downloads successfully

#### Advanced Sharing Test
```bash
# Test share link with curl
SHARE_URL="[copy from web interface]"
curl -I "$SHARE_URL"
# Expected: HTTP/1.1 200 OK (share page loads)
```

## Backend Verification Commands

### Database State Verification
```bash
# Count registered users
sqlite3 /opt/arkfile/var/lib/database/arkfile.db \
  "SELECT COUNT(*) FROM users;"

# List all files (encrypted metadata)
sqlite3 /opt/arkfile/var/lib/database/arkfile.db \
  "SELECT file_name, encrypted, created_at FROM files;"

# Check OPAQUE envelopes
sqlite3 /opt/arkfile/var/lib/database/arkfile.db \
  "SELECT email, envelope_length FROM users;"
```

### Storage Backend Verification
```bash
# Check MinIO connectivity
curl -I http://localhost:9000/minio/health/ready
# Expected: HTTP/1.1 200 OK

# List storage objects (if MinIO web console enabled)
curl -X GET http://localhost:9000/arkfile-storage/ \
  --user minioadmin:minioadmin
```

### Key Material Verification
```bash
# Verify OPAQUE server keys
ls -la /opt/arkfile/etc/keys/opaque/
# Should show: server_private.key with 600 permissions

# Verify JWT keys
ls -la /opt/arkfile/etc/keys/jwt/current/
# Should show: signing.key and public.key

# Check key file integrity
openssl pkey -in /opt/arkfile/etc/keys/jwt/current/signing.key -check
# Expected: "Key is valid"
```

## Troubleshooting Common Issues

### Issue: "Connection refused" on any URL

**Diagnosis**:
```bash
sudo systemctl status arkfile
sudo journalctl -u arkfile --since="5 minutes ago"
```

**Solutions**:
1. Start the service: `sudo systemctl start arkfile`
2. Check configuration: `/opt/arkfile/etc/config.yaml`
3. Verify port availability: `sudo netstat -tlnp | grep :8080`

### Issue: HTTPS certificate warnings won't accept

**Diagnosis**: Browser certificate cache or security policy

**Solutions**:
1. Try incognito/private browsing mode
2. Clear browser certificate cache
3. Test with different browser
4. Use HTTP mode for testing: `http://localhost:8080`

### Issue: OPAQUE registration fails

**Diagnosis**:
```bash
# Check OPAQUE key availability
sudo -u arkfile test -r /opt/arkfile/etc/keys/opaque/server_private.key
echo $?  # Should be 0

# Check WebAssembly loading
curl -I http://localhost:8080/wasm_exec.js
# Expected: HTTP/1.1 200 OK
```

**Solutions**:
1. Regenerate OPAQUE keys: `sudo ./scripts/setup-opaque-keys.sh`
2. Check browser JavaScript console for WebAssembly errors
3. Test with different browser

### Issue: File upload fails

**Diagnosis**:
```bash
# Check storage connectivity
curl -I http://localhost:9000/minio/health/ready

# Check disk space
df -h /opt/arkfile/
```

**Solutions**:
1. Restart MinIO: `sudo systemctl restart minio@arkfile`
2. Check storage permissions: `ls -la /opt/arkfile/var/lib/storage/`
3. Verify MinIO configuration in `/opt/arkfile/etc/config.yaml`

### Issue: Database errors

**Diagnosis**:
```bash
# Check database file
ls -la /opt/arkfile/var/lib/database/arkfile.db

# Test database connectivity
sqlite3 /opt/arkfile/var/lib/database/arkfile.db ".tables"
```

**Solutions**:
1. Check database permissions: `sudo chown arkfile:arkfile /opt/arkfile/var/lib/database/arkfile.db`
2. Reinitialize schema: Apply `database/schema_extensions.sql`
3. Check available disk space

## Production Readiness Checklist

After successful validation, prepare for production:

### Security Hardening
- [ ] Replace self-signed certificates with Let's Encrypt or commercial certificates
- [ ] Configure firewall rules (ports 80, 443 only)
- [ ] Set up automated backups
- [ ] Configure log rotation
- [ ] Run security audit: `./scripts/security-audit.sh`

### Monitoring Setup
- [ ] Configure health check monitoring
- [ ] Set up alerting for service failures
- [ ] Configure log aggregation
- [ ] Set up performance monitoring

### Backup Procedures  
- [ ] Test key backup: `./scripts/backup-keys.sh`
- [ ] Test database backup
- [ ] Document recovery procedures
- [ ] Test restore process

## Certificate Upgrade for Production

When ready for production with a real domain:

```bash
# Option 1: Let's Encrypt (Recommended)
sudo ./scripts/setup-tls-certs.sh --production \
  --domain your-domain.com --letsencrypt

# Option 2: Commercial Certificate
sudo ./scripts/setup-tls-certs.sh --production \
  --domain your-domain.com \
  --cert-file /path/to/your-cert.pem \
  --key-file /path/to/your-private-key.pem
```

## Support Resources

- **Health Dashboard**: `http://localhost:8080/health`
- **Security Audit**: `./scripts/security-audit.sh`
- **Emergency Procedures**: `./scripts/emergency-procedures.sh`
- **Performance Testing**: `./scripts/performance-benchmark.sh`
- **Log Files**: `/var/log/arkfile/` and `sudo journalctl -u arkfile`

---

## Success Criteria

✅ **Deployment is successful when**:
1. All services show "active (running)" status
2. Health endpoint returns "healthy" for all checks
3. User can register with OPAQUE protocol
4. User can login and access file interface
5. File upload, encryption, and download work correctly
6. File sharing links work in incognito mode
7. Backend verification commands show expected data

🎉 **Congratulations!** Your Arkfile deployment is validated and ready for use.

For production deployment, follow the certificate upgrade procedures and security hardening checklist above.
