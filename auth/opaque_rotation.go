package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/models"
)

// OpaqueRotationResult reports the outcome of a deployment-wide OPAQUE key
// rotation (flag all accounts + replace server keys).
type OpaqueRotationResult struct {
	UsersFlagged          int64
	Usernames             []string
	PrivateKeyFingerprint string
	OPRFSeedFingerprint   string
	PreviousPrivateKeyFP  string
	PreviousOPRFSeedFP    string
}

// OpaqueKeyReplaceResult reports the outcome of replacing only the server keys.
type OpaqueKeyReplaceResult struct {
	PrivateKeyFingerprint string
	OPRFSeedFingerprint   string
	PreviousPrivateKeyFP  string
	PreviousOPRFSeedFP    string
}

// VerifyOpaqueKeyRotationPreconditions ensures every active account is flagged
// for re-registration and no OPAQUE user records remain. Replacing server keys
// before these conditions hold routes logins through DeriveFakeUserRecord instead
// of the structured account_requires_reregistration response.
func VerifyOpaqueKeyRotationPreconditions(db *sql.DB) error {
	var unflagged int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM users WHERE deleted_at IS NULL AND requires_reregistration = false`,
	).Scan(&unflagged)
	if err != nil {
		return fmt.Errorf("failed to count unflagged users: %w", err)
	}
	if unflagged > 0 {
		return fmt.Errorf(
			"refusing to replace OPAQUE server keys: %d active account(s) are not flagged for re-registration; run flag-user-reregistration --all first, or use rotate-opaque-keys rotate for the atomic flow",
			unflagged,
		)
	}

	var remainingRecords int
	err = db.QueryRow(`SELECT COUNT(*) FROM opaque_user_data`).Scan(&remainingRecords)
	if err != nil {
		return fmt.Errorf("failed to count opaque user records: %w", err)
	}
	if remainingRecords > 0 {
		return fmt.Errorf(
			"refusing to replace OPAQUE server keys: %d opaque_user_data row(s) still present; run flag-user-reregistration --all first to clear them",
			remainingRecords,
		)
	}

	return nil
}

// ReplaceOpaqueServerKeys generates fresh OPAQUE server key material, overwriting
// the two system_keys rows, verifies the material changed, and reloads the
// in-memory keys without a restart.
func ReplaceOpaqueServerKeys() (OpaqueKeyReplaceResult, error) {
	var result OpaqueKeyReplaceResult

	km, err := crypto.GetKeyManager()
	if err != nil {
		return result, fmt.Errorf("failed to get KeyManager: %w", err)
	}

	oldPriv, err := km.GetKey(OpaqueServerPrivateKeyID, OpaqueKeyType)
	if err != nil {
		return result, fmt.Errorf("failed to read current opaque server private key: %w", err)
	}
	oldSeed, err := km.GetKey(OpaqueOPRFSeedKeyID, OpaqueKeyType)
	if err != nil {
		return result, fmt.Errorf("failed to read current opaque oprf seed: %w", err)
	}
	result.PreviousPrivateKeyFP = opaqueKeyFingerprint(oldPriv)
	result.PreviousOPRFSeedFP = opaqueKeyFingerprint(oldSeed)

	newPriv := make([]byte, opaqueServerPrivateKeySize)
	newSeed := make([]byte, opaqueOPRFSeedSize)
	if _, err := io.ReadFull(rand.Reader, newPriv); err != nil {
		return result, fmt.Errorf("failed to generate new opaque server private key: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, newSeed); err != nil {
		return result, fmt.Errorf("failed to generate new opaque oprf seed: %w", err)
	}

	if err := km.StoreKey(OpaqueServerPrivateKeyID, OpaqueKeyType, newPriv); err != nil {
		return result, fmt.Errorf("failed to store new opaque server private key: %w", err)
	}
	if err := km.StoreKey(OpaqueOPRFSeedKeyID, OpaqueKeyType, newSeed); err != nil {
		return result, fmt.Errorf("failed to store new opaque oprf seed: %w", err)
	}

	storedPriv, err := km.GetKey(OpaqueServerPrivateKeyID, OpaqueKeyType)
	if err != nil {
		return result, fmt.Errorf("failed to verify new opaque server private key: %w", err)
	}
	storedSeed, err := km.GetKey(OpaqueOPRFSeedKeyID, OpaqueKeyType)
	if err != nil {
		return result, fmt.Errorf("failed to verify new opaque oprf seed: %w", err)
	}

	if bytes.Equal(storedPriv, oldPriv) {
		return result, fmt.Errorf("opaque server private key was not replaced")
	}
	if bytes.Equal(storedSeed, oldSeed) {
		return result, fmt.Errorf("opaque oprf seed was not replaced")
	}
	if !bytes.Equal(storedPriv, newPriv) || !bytes.Equal(storedSeed, newSeed) {
		return result, fmt.Errorf("stored OPAQUE keys do not match generated material")
	}

	if err := ReloadOpaqueServerKeys(); err != nil {
		return result, fmt.Errorf("keys replaced in database but in-memory reload failed: %w", err)
	}

	result.PrivateKeyFingerprint = opaqueKeyFingerprint(storedPriv)
	result.OPRFSeedFingerprint = opaqueKeyFingerprint(storedSeed)
	return result, nil
}

// ReplaceOpaqueServerKeysGuarded replaces server keys only when every active
// account is already flagged and opaque_user_data is empty.
func ReplaceOpaqueServerKeysGuarded(db *sql.DB) (OpaqueKeyReplaceResult, error) {
	var result OpaqueKeyReplaceResult
	if err := VerifyOpaqueKeyRotationPreconditions(db); err != nil {
		return result, err
	}
	return ReplaceOpaqueServerKeys()
}

// RotateOpaqueServerKeysDeployment performs the recommended atomic deployment
// rotation: flag every active account, clear all OPAQUE user records, replace
// the server keys, and reload them in memory. Callers should force-logout the
// returned usernames so sessions pick up the new state immediately.
func RotateOpaqueServerKeysDeployment(db *sql.DB) (OpaqueRotationResult, error) {
	var result OpaqueRotationResult

	usernames, err := listActiveUsernames(db)
	if err != nil {
		return result, fmt.Errorf("failed to list active users: %w", err)
	}
	result.Usernames = usernames

	tx, err := db.Begin()
	if err != nil {
		return result, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM opaque_user_data`); err != nil {
		return result, fmt.Errorf("failed to clear opaque user records: %w", err)
	}

	flagged, err := models.FlagAllUsersForReregistration(tx)
	if err != nil {
		return result, fmt.Errorf("failed to flag users for re-registration: %w", err)
	}
	result.UsersFlagged = flagged

	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("failed to commit user flagging: %w", err)
	}

	replaceResult, err := ReplaceOpaqueServerKeys()
	if err != nil {
		return result, err
	}

	result.PrivateKeyFingerprint = replaceResult.PrivateKeyFingerprint
	result.OPRFSeedFingerprint = replaceResult.OPRFSeedFingerprint
	result.PreviousPrivateKeyFP = replaceResult.PreviousPrivateKeyFP
	result.PreviousOPRFSeedFP = replaceResult.PreviousOPRFSeedFP
	return result, nil
}

func listActiveUsernames(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT username FROM users WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var usernames []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		usernames = append(usernames, u)
	}
	return usernames, rows.Err()
}

func opaqueKeyFingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}
