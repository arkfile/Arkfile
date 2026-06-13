package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/84adam/Arkfile/crypto"
)

// ApplyTier3MasterRotationOptions configures offline Tier-3 master rotation.
type ApplyTier3MasterRotationOptions struct {
	BaseDir          string
	MasterKeyPath    string
	Mandate          string
	DB               *sql.DB
	SkipServiceCheck bool
	ServiceName      string
	BackupDirectory  string
	MasterKeyUID     int
	MasterKeyGID     int
}

// ApplyTier3MasterRotation performs mandate-gated Tier-3 master rotation with DB re-encryption.
func ApplyTier3MasterRotation(opts ApplyTier3MasterRotationOptions) (crypto.Tier3RotationStats, error) {
	var stats crypto.Tier3RotationStats

	if opts.DB == nil {
		return stats, fmt.Errorf("database handle is required")
	}
	if opts.Mandate == "" {
		return stats, fmt.Errorf("rotation mandate is required")
	}
	if opts.BaseDir == "" {
		opts.BaseDir = "/opt/arkfile"
	}
	if opts.MasterKeyPath == "" {
		opts.MasterKeyPath = filepath.Join(opts.BaseDir, "etc", "keys", "user-secret-master.bin")
	}
	if opts.ServiceName == "" {
		opts.ServiceName = "arkfile"
	}
	if opts.BackupDirectory == "" {
		opts.BackupDirectory = filepath.Join(opts.BaseDir, "backups", "user-secret-rotation")
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

	if err := LoadJWTFullKeys(); err != nil {
		return stats, fmt.Errorf("failed to load JWT verification keys: %w", err)
	}

	payload, err := VerifyTier3RotationMandate(opts.Mandate, GetJWTFullPublicKey())
	if err != nil {
		return stats, err
	}

	if err := ConsumeTier3RotationMandate(opts.DB, payload.Nonce); err != nil {
		return stats, err
	}

	oldMaster, err := crypto.ReadTier3MasterFile(opts.MasterKeyPath)
	if err != nil {
		return stats, err
	}
	defer crypto.SecureClear(oldMaster)

	newMaster := make([]byte, 32)
	if _, err := rand.Read(newMaster); err != nil {
		return stats, fmt.Errorf("failed to generate new Tier-3 master key: %w", err)
	}
	defer crypto.SecureClear(newMaster)

	if err := os.MkdirAll(opts.BackupDirectory, 0700); err != nil {
		return stats, fmt.Errorf("failed to create backup directory: %w", err)
	}
	timestamp := time.Now().UTC().Format("20060102_150405")
	backupPath := filepath.Join(opts.BackupDirectory, "user-secret-master-"+timestamp+".bin")
	if err := copyRotationFile(opts.MasterKeyPath, backupPath); err != nil {
		return stats, fmt.Errorf("failed to backup current master key: %w", err)
	}

	stats, err = crypto.ReencryptAllTier3WrappedRows(opts.DB, oldMaster, newMaster)
	if err != nil {
		return stats, fmt.Errorf("database re-encryption failed: %w", err)
	}

	if err := crypto.WriteTier3MasterFile(opts.MasterKeyPath, newMaster, opts.MasterKeyUID, opts.MasterKeyGID); err != nil {
		return stats, fmt.Errorf("failed to install new Tier-3 master key: %w", err)
	}

	if err := verifyTier3RotationSample(opts.DB, newMaster); err != nil {
		return stats, fmt.Errorf("post-rotation verification failed: %w", err)
	}

	return stats, nil
}

func verifyTier3RotationSample(db *sql.DB, newMaster []byte) error {
	var username string
	var credentialData []byte
	err := db.QueryRow(`SELECT username, credential_data FROM user_mfa_credentials LIMIT 1`).Scan(&username, &credentialData)
	if err == nil {
		key, kerr := crypto.DeriveMFAUserKeyFromMaster(newMaster, username)
		if kerr != nil {
			return kerr
		}
		defer crypto.SecureZeroMFAKey(key)
		if decoded, derr := decodeRotationBase64Ciphertext(credentialData); derr == nil {
			credentialData = decoded
		}
		if _, derr := crypto.DecryptGCM(credentialData, key); derr != nil {
			return fmt.Errorf("MFA verification decrypt failed for %s: %w", username, derr)
		}
	} else if err != sql.ErrNoRows {
		return err
	}

	var dataB64, nonceB64 string
	err = db.QueryRow(`SELECT encrypted_data, nonce FROM user_contact_info LIMIT 1`).Scan(&dataB64, &nonceB64)
	if err == nil {
		key, kerr := crypto.DeriveTier3SubkeyFromMaster(newMaster, []byte("contact_info"))
		if kerr != nil {
			return kerr
		}
		defer crypto.SecureClear(key)
		ciphertext, derr := decodeContactPartsForVerify(dataB64, nonceB64)
		if derr != nil {
			return derr
		}
		if _, derr := crypto.DecryptGCM(ciphertext, key); derr != nil {
			return fmt.Errorf("contact info verification decrypt failed: %w", derr)
		}
	} else if err != sql.ErrNoRows {
		return err
	}

	return nil
}

func decodeRotationBase64Ciphertext(data []byte) ([]byte, error) {
	if len(data) > 60 && len(data)%4 == 0 {
		isBase64 := true
		for _, b := range data {
			if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
				(b >= '0' && b <= '9') || b == '+' || b == '/' || b == '=') {
				isBase64 = false
				break
			}
		}
		if isBase64 {
			decoded, err := base64.StdEncoding.DecodeString(string(data))
			if err == nil {
				return decoded, nil
			}
		}
	}
	return data, nil
}

func decodeContactPartsForVerify(dataB64, nonceB64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, err
	}
	return append(nonce, ciphertext...), nil
}

func isSystemdServiceActive(serviceName string) (bool, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, nil
	}
	out, err := exec.Command("systemctl", "is-active", serviceName).Output()
	if err != nil {
		state := strings.TrimSpace(string(out))
		if state == "inactive" || state == "failed" || state == "deactivating" {
			return false, nil
		}
		return false, nil
	}
	state := strings.TrimSpace(string(out))
	return state == "active" || state == "activating", nil
}

func copyRotationFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0400)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
