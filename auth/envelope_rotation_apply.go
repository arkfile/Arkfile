package auth

import (
	"bufio"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/84adam/Arkfile/crypto"
)

const masterKeyEnvName = "ARKFILE_MASTER_KEY"

// ApplyEnvelopeMasterRotationOptions configures offline envelope master rotation.
type ApplyEnvelopeMasterRotationOptions struct {
	BaseDir          string
	SecretsEnvPath   string
	Mandate          string
	DB               *sql.DB
	SkipServiceCheck bool
	ServiceName      string
	BackupDirectory  string
}

// ApplyEnvelopeMasterRotation performs mandate-gated envelope master key rotation.
// With the service stopped it re-wraps every system_keys row under a freshly
// generated master (regenerating the EntityID master), writes the new master to a
// root-only recovery file before committing so it can never be lost, backs up
// secrets.env, swaps in the new ARKFILE_MASTER_KEY value, and verifies the whole
// table decrypts under the new master.
func ApplyEnvelopeMasterRotation(opts ApplyEnvelopeMasterRotationOptions) (crypto.EnvelopeRotationStats, error) {
	var stats crypto.EnvelopeRotationStats

	if opts.DB == nil {
		return stats, fmt.Errorf("database handle is required")
	}
	if opts.Mandate == "" {
		return stats, fmt.Errorf("rotation mandate is required")
	}
	if opts.BaseDir == "" {
		opts.BaseDir = "/opt/arkfile"
	}
	if opts.SecretsEnvPath == "" {
		opts.SecretsEnvPath = filepath.Join(opts.BaseDir, "etc", "secrets.env")
	}
	if opts.ServiceName == "" {
		opts.ServiceName = "arkfile"
	}
	if opts.BackupDirectory == "" {
		opts.BackupDirectory = filepath.Join(opts.BaseDir, "backups", "envelope-rotation")
	}

	if !opts.SkipServiceCheck {
		active, err := isSystemdServiceActive(opts.ServiceName)
		if err != nil {
			return stats, err
		}
		if active {
			return stats, fmt.Errorf("%s service is still running; stop it before apply", opts.ServiceName)
		}
	}

	// The current master is the authoritative value in secrets.env. It must match
	// the master the running KeyManager was initialized with, since the rows were
	// wrapped under it.
	oldMaster, err := readMasterKeyFromSecretsEnv(opts.SecretsEnvPath)
	if err != nil {
		return stats, err
	}
	defer crypto.SecureClear(oldMaster)

	// Mandate verification reads the JWT verification keys out of system_keys,
	// which are still wrapped under the old master at this point.
	if err := LoadJWTFullKeys(); err != nil {
		return stats, fmt.Errorf("failed to load JWT verification keys: %w", err)
	}
	payload, err := VerifyEnvelopeRotationMandate(opts.Mandate, GetJWTFullPublicKey())
	if err != nil {
		return stats, err
	}
	if err := ConsumeEnvelopeRotationMandate(opts.DB, payload.Nonce); err != nil {
		return stats, err
	}

	newMaster := make([]byte, 32)
	if _, err := rand.Read(newMaster); err != nil {
		return stats, fmt.Errorf("failed to generate new envelope master key: %w", err)
	}
	defer crypto.SecureClear(newMaster)

	if err := os.MkdirAll(opts.BackupDirectory, 0700); err != nil {
		return stats, fmt.Errorf("failed to create backup directory: %w", err)
	}
	timestamp := time.Now().UTC().Format("20060102_150405")

	// Persist the new master to a root-only recovery file BEFORE committing the
	// re-encryption. If the secrets.env rewrite later fails, the operator can
	// recover the deployment by installing this value manually.
	recoveryPath := filepath.Join(opts.BackupDirectory, "envelope-master-"+timestamp+".new")
	if err := os.WriteFile(recoveryPath, []byte(hex.EncodeToString(newMaster)+"\n"), 0400); err != nil {
		return stats, fmt.Errorf("failed to write new-master recovery file: %w", err)
	}

	// Back up the entire secrets.env before rewriting it.
	secretsBackupPath := filepath.Join(opts.BackupDirectory, "secrets.env-"+timestamp)
	if err := copySecretsEnvFile(opts.SecretsEnvPath, secretsBackupPath); err != nil {
		return stats, fmt.Errorf("failed to back up secrets.env: %w", err)
	}

	stats, err = crypto.ReencryptAllSystemKeys(opts.DB, oldMaster, newMaster)
	if err != nil {
		return stats, fmt.Errorf("system_keys re-encryption failed: %w", err)
	}

	if err := rewriteMasterKeyInSecretsEnv(opts.SecretsEnvPath, hex.EncodeToString(newMaster)); err != nil {
		return stats, fmt.Errorf("failed to install new master key in secrets.env (recover from %s): %w", recoveryPath, err)
	}

	if _, err := crypto.VerifyAllSystemKeysDecryptable(opts.DB, newMaster); err != nil {
		return stats, fmt.Errorf("post-rotation verification failed: %w", err)
	}

	return stats, nil
}

// readMasterKeyFromSecretsEnv parses ARKFILE_MASTER_KEY from secrets.env and
// returns the decoded 32-byte master key.
func readMasterKeyFromSecretsEnv(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open secrets env file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, masterKeyEnvName+"=") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, masterKeyEnvName+"="))
		master, derr := hex.DecodeString(value)
		if derr != nil {
			return nil, fmt.Errorf("failed to decode %s: %w", masterKeyEnvName, derr)
		}
		if len(master) != 32 {
			return nil, fmt.Errorf("%s must be 32 bytes (64 hex chars), got %d bytes", masterKeyEnvName, len(master))
		}
		return master, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%s not found in %s", masterKeyEnvName, path)
}

// rewriteMasterKeyInSecretsEnv replaces only the ARKFILE_MASTER_KEY line in
// secrets.env, preserving every other line and comment, and restores the file's
// original mode and ownership. The write is staged to a temp file and renamed so
// a partial write can never leave a corrupt secrets.env.
func rewriteMasterKeyInSecretsEnv(path, newHex string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), masterKeyEnvName+"=") {
			lines[i] = masterKeyEnvName + "=" + newHex
			replaced = true
			break
		}
	}
	if !replaced {
		return fmt.Errorf("%s line not found in %s", masterKeyEnvName, path)
	}

	tmpPath := path + ".rotate.tmp"
	if err := os.WriteFile(tmpPath, []byte(strings.Join(lines, "\n")), info.Mode().Perm()); err != nil {
		return err
	}

	// Best-effort restore of original ownership (no-op when not running as root
	// or when uid/gid already match).
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(tmpPath, int(st.Uid), int(st.Gid))
	}
	if err := os.Chmod(tmpPath, info.Mode().Perm()); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// copySecretsEnvFile copies secrets.env to a 0600 backup.
func copySecretsEnvFile(src, dst string) error {
	content, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, content, 0600)
}
