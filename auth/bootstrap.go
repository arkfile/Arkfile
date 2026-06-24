package auth

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/arkfile/Arkfile/crypto"
)

// BootstrapTokenPath is the on-disk delivery channel for the bootstrap token.
//
// The token MUST NOT be logged to stdout or journald, because any operator or attacker
// with `journalctl` access on the host would otherwise be able to harvest it.
// Instead, CheckAndGenerateBootstrapToken writes the hex-encoded token to this file
// (mode 0400, owned by the arkfile process user) and the operator reads it back with `sudo cat`.
//
// Tests override this via a package-private setter to point at a temp file.
var BootstrapTokenPath = "/opt/arkfile/etc/keys/bootstrap-token.bin"

// setBootstrapTokenPathForTest lets tests redirect the token file to a temp
// location. Returns a restore function that the test should defer.
func setBootstrapTokenPathForTest(path string) func() {
	prev := BootstrapTokenPath
	BootstrapTokenPath = path
	return func() { BootstrapTokenPath = prev }
}

// CheckAndGenerateBootstrapToken checks if the system needs bootstrapping.
// Bootstrap mode is enabled when:
// 1. No ACTIVE admin users exist (users with last_login set), OR
// 2. ARKFILE_FORCE_ADMIN_BOOTSTRAP environment variable is set to "true"
//
// This function is safe for multi-instance deployments - it checks if a bootstrap
// token already exists before generating a new one, preventing multiple tokens
// from being written.
//
// The token is delivered to the operator via the on-disk file at
// BootstrapTokenPath (mode 0400). The token is NEVER logged to stdout or the
// systemd journal.
func CheckAndGenerateBootstrapToken(db *sql.DB) error {
	// Check for force bootstrap override
	forceBootstrap := strings.ToLower(os.Getenv("ARKFILE_FORCE_ADMIN_BOOTSTRAP")) == "true"

	// Check for ACTIVE admins (those who have successfully logged in)
	var activeAdminCount int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM users WHERE is_admin = true AND last_login IS NOT NULL",
	).Scan(&activeAdminCount)
	if err != nil {
		return fmt.Errorf("failed to check active admin count: %w", err)
	}

	km, err := crypto.GetKeyManager()
	if err != nil {
		return fmt.Errorf("failed to get key manager: %w", err)
	}

	// Check if bootstrap token already exists (prevents race condition in
	// multi-instance deployments and avoids rewriting the file every restart).
	existingToken, err := km.GetKey("bootstrap_token", "bootstrap")
	if err == nil && len(existingToken) > 0 {
		if !forceBootstrap {
			// Token already exists; do not regenerate. Do not re-emit the
			// file either -- if an operator already consumed the original
			// file, re-writing it here would be a silent confusion source.
			// If the file is missing in this branch, the operator must
			// explicitly request regeneration with ARKFILE_FORCE_ADMIN_BOOTSTRAP=true.
			log.Printf("[BOOTSTRAP] Bootstrap token already exists. Use ARKFILE_FORCE_ADMIN_BOOTSTRAP=true to regenerate.")
			return nil
		}
		// Force bootstrap requested -- regenerate below.
		log.Printf("[BOOTSTRAP] Force bootstrap enabled - regenerating token")
	}

	// Only generate token if no active admins OR force flag is set
	if activeAdminCount > 0 && !forceBootstrap {
		log.Printf("[BOOTSTRAP] Active admin users detected. Bootstrap mode disabled.")
		log.Printf("[BOOTSTRAP] Set ARKFILE_FORCE_ADMIN_BOOTSTRAP=true to override.")

		// Ensure bootstrap token is removed from both the DB and the
		// on-disk delivery file. A leftover file would otherwise sit at
		// mode 0400 indefinitely with no live token behind it.
		if err := km.DeleteKey("bootstrap_token"); err != nil {
			log.Printf("Warning: Failed to cleanup bootstrap token: %v", err)
		}
		if err := os.Remove(BootstrapTokenPath); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: Failed to remove stale bootstrap token file %s: %v", BootstrapTokenPath, err)
		}
		return nil
	}

	// Generate bootstrap token (32 random bytes -> 64 hex chars)
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("failed to generate bootstrap token: %w", err)
	}

	// Store in system_keys (REPLACE INTO ensures database-level atomicity).
	// consumed_at defaults to NULL on a fresh row; the redeem path in
	// handlers/bootstrap.go sets it atomically inside the first-admin
	// transaction (single-use enforcement).
	if err := km.StoreKey("bootstrap_token", "bootstrap", token); err != nil {
		return fmt.Errorf("failed to store bootstrap token: %w", err)
	}

	tokenHex := hex.EncodeToString(token)

	if err := writeBootstrapTokenFile(tokenHex); err != nil {
		// Roll back the DB row so the operator is not left with a token
		// they cannot read; otherwise the next startup would skip
		// regeneration and the system would be unbootstrappable.
		if delErr := km.DeleteKey("bootstrap_token"); delErr != nil {
			log.Printf("Warning: failed to roll back bootstrap_token row after file-write error: %v", delErr)
		}
		return fmt.Errorf("failed to write bootstrap token file: %w", err)
	}

	if forceBootstrap {
		log.Printf("[BOOTSTRAP] ARKFILE_FORCE_ADMIN_BOOTSTRAP enabled - bootstrap token regenerated")
	}
	log.Printf("[BOOTSTRAP] System is in Bootstrap Mode.")
	log.Printf("[BOOTSTRAP] Token written to %s (mode 0400) -- read with: sudo cat %s", BootstrapTokenPath, BootstrapTokenPath)

	return nil
}

// writeBootstrapTokenFile writes the hex-encoded token to BootstrapTokenPath
// with mode 0400 and (best-effort) ownership of the arkfile process user.
//
// The path's parent directory is expected to exist (the deploy scripts create
// /opt/arkfile/etc/keys with mode 0700 owned by the arkfile user). If the
// parent is missing this returns an error rather than creating it, because a
// missing parent indicates a deploy-script bug we should surface, not paper
// over.
func writeBootstrapTokenFile(tokenHex string) error {
	dir := filepath.Dir(BootstrapTokenPath)
	if info, err := os.Stat(dir); err != nil {
		return fmt.Errorf("bootstrap token directory %s missing: %w", dir, err)
	} else if !info.IsDir() {
		return fmt.Errorf("bootstrap token parent %s is not a directory", dir)
	}

	// Write atomically via a sibling temp file + rename so we never leave a
	// half-written token on disk if the process is killed mid-write.
	tmp, err := os.CreateTemp(dir, ".bootstrap-token-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file for bootstrap token: %w", err)
	}
	tmpPath := tmp.Name()
	cleanupTmp := func() {
		_ = os.Remove(tmpPath)
	}

	if err := tmp.Chmod(0o400); err != nil {
		tmp.Close()
		cleanupTmp()
		return fmt.Errorf("failed to chmod 0400 on bootstrap token temp file: %w", err)
	}
	if _, err := tmp.WriteString(tokenHex + "\n"); err != nil {
		tmp.Close()
		cleanupTmp()
		return fmt.Errorf("failed to write bootstrap token bytes: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanupTmp()
		return fmt.Errorf("failed to fsync bootstrap token temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanupTmp()
		return fmt.Errorf("failed to close bootstrap token temp file: %w", err)
	}

	// Best-effort chown to the arkfile user. Only attempt this when it can
	// actually succeed; otherwise we'd just be logging warnings for cases
	// the kernel is guaranteed to refuse.
	//
	//   - Skip when current UID/GID already match the arkfile user (the
	//     production case: systemd runs Arkfile as User=arkfile). The chown
	//     would be a no-op identity operation.
	//   - Skip when we're not root and we'd be chowning to a different
	//     user (developer-machine test case, including `go test`). The
	//     kernel returns EPERM by design; the warning is non-actionable.
	//
	// The remaining case -- running as root AND target UID/GID differs --
	// is the only situation where chown can do real work AND can fail in
	// an interesting way (e.g. filesystem doesn't support ownership). Only
	// in that case do we log on failure.
	if uid, gid, ok := lookupArkfileUIDGID(); ok {
		curUID := os.Getuid()
		curGID := os.Getgid()
		if curUID != uid || curGID != gid {
			if curUID == 0 {
				_ = os.Chown(tmpPath, uid, gid)
			}
			// non-root + mismatched target: kernel guarantees EPERM; no-op.
		}
		// matched target: chown would be identity; no-op.
	}

	if err := os.Rename(tmpPath, BootstrapTokenPath); err != nil {
		cleanupTmp()
		return fmt.Errorf("failed to rename bootstrap token into place: %w", err)
	}

	return nil
}

// lookupArkfileUIDGID returns the numeric UID/GID of the "arkfile" system user
// and group, if present. Returns ok=false when running in test environments
// where these accounts don't exist; callers should treat that as "skip chown".
func lookupArkfileUIDGID() (int, int, bool) {
	uid := -1
	gid := -1

	// Parse /etc/passwd directly in pure Go to avoid CGO glibc NSS lookup segfaults on static builds
	passwdFile, err := os.Open("/etc/passwd")
	if err == nil {
		defer passwdFile.Close()
		scanner := bufio.NewScanner(passwdFile)
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Split(line, ":")
			if len(parts) >= 4 && parts[0] == "arkfile" {
				if parsedUID, err := strconv.Atoi(parts[2]); err == nil {
					uid = parsedUID
				}
				if parsedGID, err := strconv.Atoi(parts[3]); err == nil {
					gid = parsedGID
				}
				break
			}
		}
	}

	// Falls back to /etc/group for GID if passwd lookup failed or group has different GID
	if gid == -1 {
		groupFile, err := os.Open("/etc/group")
		if err == nil {
			defer groupFile.Close()
			scanner := bufio.NewScanner(groupFile)
			for scanner.Scan() {
				line := scanner.Text()
				parts := strings.Split(line, ":")
				if len(parts) >= 3 && parts[0] == "arkfile" {
					if parsedGID, err := strconv.Atoi(parts[2]); err == nil {
						gid = parsedGID
					}
					break
				}
			}
		}
	}

	if uid != -1 && gid != -1 {
		return uid, gid, true
	}
	return 0, 0, false
}

// ValidateBootstrapToken checks if the provided token matches the stored
// bootstrap token AND has not yet been consumed by a successful first-admin
// registration.
//
// Uses constant-time comparison on the token bytes themselves; the consumed_at
// check is performed via a separate, cheap DB query that runs only after the
// constant-time compare succeeds.
//
// The token is single-use. Once handlers/bootstrap.go atomically
// sets consumed_at inside the admin-creation transaction, every subsequent
// validation returns (false, nil).
func ValidateBootstrapToken(tokenHex string) (bool, error) {
	km, err := crypto.GetKeyManager()
	if err != nil {
		return false, err
	}

	storedToken, err := km.GetKey("bootstrap_token", "bootstrap")
	if err != nil {
		// If key not found, bootstrap is disabled
		return false, nil
	}

	providedToken, err := hex.DecodeString(tokenHex)
	if err != nil {
		return false, nil // Invalid hex
	}

	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(storedToken, providedToken) != 1 {
		return false, nil
	}

	// Token matches -- but reject if it has already been consumed.
	consumed, err := isBootstrapTokenConsumed(km)
	if err != nil {
		// On query error, fail closed: do not allow bootstrap.
		return false, err
	}
	if consumed {
		return false, nil
	}

	return true, nil
}

// isBootstrapTokenConsumed returns true if the system_keys row for the
// bootstrap token has a non-NULL consumed_at timestamp. The KeyManager does
// not expose this column directly, so we query it via the underlying *sql.DB.
func isBootstrapTokenConsumed(km *crypto.KeyManager) (bool, error) {
	db := km.DB()
	if db == nil {
		return false, fmt.Errorf("key manager has no database handle")
	}
	var consumedAt sql.NullString
	err := db.QueryRow(
		"SELECT consumed_at FROM system_keys WHERE key_id = ?",
		"bootstrap_token",
	).Scan(&consumedAt)
	if err == sql.ErrNoRows {
		// No row means there is no live token to consume; ValidateBootstrapToken
		// will have already returned false from the GetKey path before we get
		// here, but handle this defensively.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to query bootstrap_token.consumed_at: %w", err)
	}
	return consumedAt.Valid && consumedAt.String != "", nil
}
