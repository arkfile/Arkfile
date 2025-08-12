# Test App Plan: Build end-to-end functionality test script: `test-app-curl.sh`

```
#!/bin/bash

# Master ArkFile App Testing Script
# Comprehensive End-to-End App Testing
#
# Flow: Cleanup → Registration → Approval → TOTP Setup → Login → 2FA Auth → 
#       Session Management → Endpoint Testing → Logout → Cleanup
#
# Features: Real TOTP codes, individual endpoint validation, mandatory TOTP enforcement,
#          database manipulation, comprehensive error handling, modular execution
```

1. first step is to get auth working for the pre-configured `arkfile-dev-admin` user
2. see 'BUG FIX TOTP SYSTEM' section below

---

# BUG FIX TOTP SYSTEM

**The Core Problem:** We have a TOTP authentication bug where the admin user cannot log in with TOTP codes. When we run the diagnostic endpoint, it shows that the admin user's TOTP data exists in the database and is marked as enabled and setup complete, but the crucial issue is `"decryptable": false` - meaning the TOTP secret cannot be decrypted with the current TOTP master key.

**The Setup/Deployment Process:** The `scripts/dev-reset.sh` script is designed to completely nuke and rebuild the development environment. It stops all services, deletes the entire database, wipes all cryptographic keys (including `/opt/arkfile/etc/keys/totp_master.key`), regenerates fresh secrets, rebuilds the application, and restarts everything. During startup, `main.go` calls `initializeAdminUser()` which creates the admin user with a fixed TOTP secret `"ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D"` and stores it encrypted in the database using the newly generated TOTP master key.

**Key Scripts in Play:** The main scripts are `scripts/dev-reset.sh` (complete environment reset), `scripts/testing/admin-auth-test.sh` (tests admin TOTP login), and the admin initialization code in `main.go` that sets up the fixed TOTP secret. The TOTP key management is handled by `crypto/totp_keys.go` which generates the master key and derives user-specific keys.

**Main Culprits We've Identified:** First, there's the suspicious `decodeBase64` function at the bottom of `auth/totp.go` that suggests there were import problems with the `encoding/base64` package. Second, there might be legacy base64 handling code in the `getTOTPData` function that's corrupting the encrypted binary data by trying to decode it as base64 when it shouldn't be. Third, there could be a race condition or timing issue between when the TOTP master key is generated and when the admin user TOTP data is encrypted.

**Remaining Questions:** The key question is whether there's buggy code in the TOTP data retrieval or storage that's corrupting the encrypted bytes, or if there's a fundamental issue with the key derivation process that causes the same username to produce different encryption keys at different times.

**Next Steps:** We need to examine the `getTOTPData` function and any base64 handling code to find where the encrypted data is being corrupted. We should also add better diagnostic logging to pinpoint exactly where the decryption is failing. Once we identify the bug, we can fix it and verify that a fresh dev-reset creates a working admin user with functional TOTP authentication.