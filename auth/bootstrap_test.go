package auth

import (
	"bytes"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/84adam/Arkfile/crypto"
	"github.com/stretchr/testify/assert"
)

// hexRegex matches any run of exactly 64 hex characters -- the wire form of
// a 32-byte bootstrap token. Used by the A-26 / F-03 regression tests to
// assert no token-shaped substring appears in log output.
var hexRegex = regexp.MustCompile(`[0-9a-fA-F]{64}`)

// captureLog runs fn while redirecting the default logger's output to a
// buffer, restoring the original output on return. The returned string is
// everything logged by `log.Printf` / `log.Print` etc. during the call.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	originalFlags := log.Flags()
	originalPrefix := log.Prefix()
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(originalFlags)
		log.SetPrefix(originalPrefix)
	}()
	fn()
	return buf.String()
}

// installTempBootstrapDB seeds the in-memory test DB (shared with auth's
// TestMain) with a user row count of 0 active admins so that
// CheckAndGenerateBootstrapToken actually writes the token. It also nukes
// any pre-existing bootstrap_token row so each test starts fresh.
//
// Returns a cleanup function the caller must defer.
func installTempBootstrapDB(t *testing.T) func() {
	t.Helper()
	km, err := crypto.GetKeyManager()
	if err != nil {
		t.Fatalf("KeyManager not initialized for test: %v", err)
	}
	db := km.DB()
	if db == nil {
		t.Fatalf("KeyManager has no DB handle")
	}

	// Make sure a `users` table exists with no active admins. The auth
	// package's TestMain (jwt_test.go) does not create one, so we add it
	// here on demand. Use CREATE TABLE IF NOT EXISTS to remain idempotent
	// across test runs in the same process.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			is_admin BOOLEAN NOT NULL DEFAULT false,
			last_login TIMESTAMP
		);
	`)
	if err != nil {
		t.Fatalf("failed to create test users table: %v", err)
	}
	if _, err := db.Exec("DELETE FROM users"); err != nil {
		t.Fatalf("failed to clear users for test: %v", err)
	}

	if _, err := db.Exec("DELETE FROM system_keys WHERE key_id = 'bootstrap_token'"); err != nil {
		t.Fatalf("failed to clear bootstrap_token for test: %v", err)
	}

	return func() {
		// Tests own the leftover rows; subsequent setups will clear.
	}
}

// TestCheckAndGenerateBootstrapToken_WritesFileNotStdout proves A-26 / F-03:
// the bootstrap token is delivered via a 0400 file at BootstrapTokenPath, and
// the 64-hex-character token value NEVER appears in any log output that
// systemd / journalctl would capture.
func TestCheckAndGenerateBootstrapToken_WritesFileNotStdout(t *testing.T) {
	cleanup := installTempBootstrapDB(t)
	defer cleanup()

	// Redirect the on-disk path to a temp file so the test doesn't touch
	// /opt/arkfile/etc/keys.
	tmpDir := t.TempDir()
	tmpPath := filepath.Join(tmpDir, "bootstrap-token.bin")
	restore := setBootstrapTokenPathForTest(tmpPath)
	defer restore()

	// Force generation regardless of existing-admin count.
	t.Setenv("ARKFILE_FORCE_ADMIN_BOOTSTRAP", "true")

	km, err := crypto.GetKeyManager()
	if err != nil {
		t.Fatalf("KeyManager not initialized: %v", err)
	}

	logged := captureLog(t, func() {
		if err := CheckAndGenerateBootstrapToken(km.DB()); err != nil {
			t.Fatalf("CheckAndGenerateBootstrapToken returned: %v", err)
		}
	})

	// A-26 / F-03: no 64-hex-char substring may appear in the log.
	if matches := hexRegex.FindAllString(logged, -1); len(matches) > 0 {
		t.Fatalf("A-26/F-03 REGRESSION: bootstrap token appears in log output. Found 64-hex match(es): %v.\nFull log:\n%s",
			matches, logged)
	}

	// The single non-secret line that points operators at the file MUST
	// be present, so they actually know where to read the token.
	assert.Contains(t, logged, tmpPath, "log output should reference the token file path")
	assert.Contains(t, logged, "mode 0400", "log output should remind the operator of the file mode")

	// The "failed to chown" warning must NOT appear in normal test runs.
	// writeBootstrapTokenFile is expected to skip the chown attempt when
	// it would be guaranteed to fail (non-root, target != self) or be a
	// no-op (current process already runs as the arkfile user). If this
	// warning shows up, the suppression logic in writeBootstrapTokenFile
	// has regressed and we're back to printing non-actionable noise.
	assert.NotContains(t, logged, "failed to chown",
		"non-actionable chown warning should be suppressed under the suppression rules; "+
			"see Option B refinement in auth/bootstrap.go writeBootstrapTokenFile")

	// File exists, mode 0400, contains a 64-hex-char token + newline.
	info, err := os.Stat(tmpPath)
	if err != nil {
		t.Fatalf("bootstrap token file missing at %s: %v", tmpPath, err)
	}
	if mode := info.Mode().Perm(); mode != 0o400 {
		t.Fatalf("bootstrap token file has mode %#o, expected 0400", mode)
	}
	if info.Size() != 65 {
		t.Fatalf("bootstrap token file has size %d, expected 65 (64 hex chars + newline)", info.Size())
	}

	// Read and verify the file's content matches what's in system_keys.
	content, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("failed to read bootstrap token file: %v", err)
	}
	tokenHex := string(content[:64])
	if !hexRegex.MatchString(tokenHex) {
		t.Fatalf("bootstrap token file content is not 64 hex chars: %q", tokenHex)
	}
	if content[64] != '\n' {
		t.Fatalf("bootstrap token file should end with newline, got byte %v", content[64])
	}

	// ValidateBootstrapToken should accept this hex string.
	ok, err := ValidateBootstrapToken(tokenHex)
	if err != nil {
		t.Fatalf("ValidateBootstrapToken returned error: %v", err)
	}
	if !ok {
		t.Fatalf("ValidateBootstrapToken rejected the just-written token; expected true")
	}

	// And the DB row matches.
	storedRaw, err := km.GetKey("bootstrap_token", "bootstrap")
	if err != nil {
		t.Fatalf("KeyManager could not read back the stored token: %v", err)
	}
	expected, err := hex.DecodeString(tokenHex)
	if err != nil {
		t.Fatalf("failed to decode token hex: %v", err)
	}
	if !bytes.Equal(storedRaw, expected) {
		t.Fatalf("file token does not match stored token")
	}
}

// TestValidateBootstrapToken_RejectsConsumedToken proves A-13:
// once the consumed_at column is set on the bootstrap_token row,
// ValidateBootstrapToken returns (false, nil) regardless of token bytes.
func TestValidateBootstrapToken_RejectsConsumedToken(t *testing.T) {
	cleanup := installTempBootstrapDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	tmpPath := filepath.Join(tmpDir, "bootstrap-token.bin")
	restore := setBootstrapTokenPathForTest(tmpPath)
	defer restore()

	t.Setenv("ARKFILE_FORCE_ADMIN_BOOTSTRAP", "true")

	km, err := crypto.GetKeyManager()
	if err != nil {
		t.Fatalf("KeyManager not initialized: %v", err)
	}

	var logged string
	logged = captureLog(t, func() {
		if err := CheckAndGenerateBootstrapToken(km.DB()); err != nil {
			t.Fatalf("failed to generate bootstrap token: %v", err)
		}
	})

	// Same suppression assertion as the file-not-stdout test: the
	// non-actionable chown warning must not appear in normal test runs.
	assert.NotContains(t, logged, "failed to chown",
		"non-actionable chown warning leaked from CheckAndGenerateBootstrapToken")

	content, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("failed to read token file: %v", err)
	}
	tokenHex := string(content[:64])

	// Before consume: token is valid.
	ok, err := ValidateBootstrapToken(tokenHex)
	if err != nil {
		t.Fatalf("ValidateBootstrapToken errored before consume: %v", err)
	}
	if !ok {
		t.Fatalf("ValidateBootstrapToken returned false before consume; expected true")
	}

	// Simulate the atomic consume that handlers/bootstrap.go performs
	// inside the first-admin transaction.
	res, err := km.DB().Exec(
		`UPDATE system_keys SET consumed_at = CURRENT_TIMESTAMP
		 WHERE key_id = 'bootstrap_token' AND consumed_at IS NULL`,
	)
	if err != nil {
		t.Fatalf("failed to mark bootstrap_token consumed: %v", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		t.Fatalf("RowsAffected error: %v", err)
	}
	if affected != 1 {
		t.Fatalf("consume UPDATE affected %d rows, want 1", affected)
	}

	// After consume: token is rejected, with no error.
	ok, err = ValidateBootstrapToken(tokenHex)
	if err != nil {
		t.Fatalf("ValidateBootstrapToken errored after consume: %v", err)
	}
	if ok {
		t.Fatalf("A-13 REGRESSION: ValidateBootstrapToken accepted a consumed token; expected false")
	}

	// And a SECOND consume attempt affects zero rows -- this is the
	// guarantee that the handler relies on to reject racing finalize calls.
	res, err = km.DB().Exec(
		`UPDATE system_keys SET consumed_at = CURRENT_TIMESTAMP
		 WHERE key_id = 'bootstrap_token' AND consumed_at IS NULL`,
	)
	if err != nil {
		t.Fatalf("second consume UPDATE errored: %v", err)
	}
	affected, err = res.RowsAffected()
	if err != nil {
		t.Fatalf("RowsAffected error: %v", err)
	}
	if affected != 0 {
		t.Fatalf("A-13 REGRESSION: second consume affected %d rows, want 0", affected)
	}
}

// TestCheckAndGenerateBootstrapToken_RemovesStaleFileWhenAdminsExist proves
// the cleanup path: once an active admin exists and force-bootstrap is off,
// the function deletes both the DB row and any leftover file at
// BootstrapTokenPath. Without this, a stale 0400 file would linger forever.
func TestCheckAndGenerateBootstrapToken_RemovesStaleFileWhenAdminsExist(t *testing.T) {
	cleanup := installTempBootstrapDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	tmpPath := filepath.Join(tmpDir, "bootstrap-token.bin")
	restore := setBootstrapTokenPathForTest(tmpPath)
	defer restore()

	km, err := crypto.GetKeyManager()
	if err != nil {
		t.Fatalf("KeyManager not initialized: %v", err)
	}

	// Step 1: generate a token (force bootstrap on).
	t.Setenv("ARKFILE_FORCE_ADMIN_BOOTSTRAP", "true")
	if err := CheckAndGenerateBootstrapToken(km.DB()); err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	if _, err := os.Stat(tmpPath); err != nil {
		t.Fatalf("expected token file at %s, got: %v", tmpPath, err)
	}

	// Step 2: simulate "active admin exists" by inserting a users row
	// with is_admin=true AND last_login set; remove the bootstrap_token
	// row so the existing-token early-return path doesn't fire.
	if _, err := km.DB().Exec(`
		INSERT INTO users (username, is_admin, last_login)
		VALUES ('admin', 1, CURRENT_TIMESTAMP)
	`); err != nil {
		t.Fatalf("failed to seed active admin: %v", err)
	}
	if _, err := km.DB().Exec(
		"DELETE FROM system_keys WHERE key_id = 'bootstrap_token'",
	); err != nil {
		t.Fatalf("failed to clear bootstrap_token row: %v", err)
	}
	t.Setenv("ARKFILE_FORCE_ADMIN_BOOTSTRAP", "false")

	if err := CheckAndGenerateBootstrapToken(km.DB()); err != nil {
		t.Fatalf("re-run failed: %v", err)
	}

	// Step 3: file must be gone.
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("expected token file to be removed at %s; got err=%v", tmpPath, err)
	}
}
