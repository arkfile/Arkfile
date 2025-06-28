# Newcomer Guide - Which Script Should I Run?

**New to Arkfile?** This guide tells you exactly which script to run based on what you want to do.

## 🚀 Just Want to Try Arkfile? (Recommended)

**Run this single command:**
```bash
./scripts/quick-start.sh
```

**What it does:**
- Sets up everything automatically
- Gives you a working web interface at http://localhost:8080
- Provides clear testing instructions
- Uses local MinIO and rqlite (no external dependencies)

**Time:** ~5 minutes  
**Requirements:** Linux with sudo access

---

## 🤔 What If I Want More Control?

### Option 1: Step-by-Step Setup
```bash
# Foundation only (users, directories, keys)
./scripts/setup-foundation.sh

# Then add services manually
sudo ./scripts/setup-minio.sh
sudo ./scripts/setup-rqlite.sh
```

### Option 2: Comprehensive Testing + Setup
```bash
./scripts/integration-test.sh
# Choose "COMPLETE" when prompted
```

### Option 3: Just Testing (No System Changes)
```bash
./scripts/integration-test.sh
# Just press Enter (testing only)
```

---

## 📋 All Available Scripts by Category

### ⭐ Start Here (Most Important)
- `quick-start.sh` - **One command to get everything working**
- `setup-foundation.sh` - Basic setup (users, directories, keys)
- `integration-test.sh` - Testing + optional complete setup
- `health-check.sh` - Check if everything is working

### 🔧 Infrastructure Setup
- `setup-users.sh` - Create system user
- `setup-directories.sh` - Create directory structure  
- `setup-minio.sh` - Set up object storage
- `setup-rqlite.sh` - Set up database

### 🔐 Security & Keys
- `setup-opaque-keys.sh` - Authentication keys
- `setup-jwt-keys.sh` - Token signing keys
- `setup-tls-certs.sh` - TLS certificates
- `backup-keys.sh` - Backup cryptographic keys

### 🧪 Testing & Validation
- `test-only.sh` - Run all tests
- `performance-benchmark.sh` - Performance testing
- `validate-deployment.sh` - Validate production setup
- `security-audit.sh` - Security check

### 🏗️ Build & Deploy
- `build.sh` - Build application
- `deploy.sh` - Production deployment
- `first-time-setup.sh` - Legacy setup script

### 🔧 Maintenance
- `rotate-jwt-keys.sh` - Key rotation
- `renew-certificates.sh` - Certificate renewal
- `emergency-procedures.sh` - Emergency response

---

## ❓ Common Questions

### "I just cloned the repo, what do I run?"
```bash
./scripts/quick-start.sh
```

### "I want to understand what's happening step by step"
```bash
./scripts/setup-foundation.sh
# Read the output and next steps
```

### "I want to test before making system changes"
```bash
./scripts/integration-test.sh
# Press Enter (testing only mode)
```

### "Something's broken, how do I debug?"
```bash
./scripts/health-check.sh
sudo journalctl -u arkfile -f
```

### "How do I know if it's working?"
After running `quick-start.sh`, you should see:
```
🎉 SETUP COMPLETE! 🎉
Your Arkfile system is now running at:
  📱 Web Interface: http://localhost:8080
```

Then visit http://localhost:8080 in your browser.

---

## 🎯 Decision Tree

```
Are you new to Arkfile?
├─ Yes → Run `./scripts/quick-start.sh`
│
└─ No → What do you want to do?
    ├─ Test the system → `./scripts/integration-test.sh` (press Enter)
    ├─ Production setup → See docs/deployment-guide.md
    ├─ Debug issues → `./scripts/health-check.sh`
    └─ Develop/contribute → `./scripts/test-only.sh`
```

---

## 📚 Where to Find More Information

### Main Documentation
- [README.md](../README.md) - Project overview
- [scripts/README.md](scripts/README.md) - Complete script reference
- [docs/setup.md](setup.md) - Detailed setup guide

### After Setup
- [docs/admin-testing-guide.md](admin-testing-guide.md) - How to test your system
- [docs/security-operations.md](security-operations.md) - Security procedures
- [docs/api.md](api.md) - API documentation

### Troubleshooting
- Check logs: `sudo journalctl -u arkfile -f`
- Health check: `./scripts/health-check.sh`
- Security audit: `./scripts/security-audit.sh`

---

## 🆘 Still Confused?

1. **Just want it working?** → `./scripts/quick-start.sh`
2. **Want to understand first?** → Read [docs/setup.md](setup.md)
3. **Having problems?** → `./scripts/health-check.sh` + check logs
4. **Need help?** → File a GitHub issue

**Bottom line:** When in doubt, run `./scripts/quick-start.sh` - it's designed to get newcomers up and running quickly with clear instructions on what to do next.
