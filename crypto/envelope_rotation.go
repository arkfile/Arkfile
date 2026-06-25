package crypto

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
)

// Envelope master rotation re-wraps every system_keys row from the old envelope
// master to a freshly generated one. The wrapping is per-row: each row's plaintext
// is decrypted under a wrapping key derived from the old master (keyed by the
// row's key_type) and re-encrypted under the equivalent wrapping key derived from
// the new master. Row values are unchanged, so the rotation is transparent to
// clients and sessions. The one exception is the EntityID master, which is
// regenerated rather than carried forward (see below).

const (
	// EntityIDMasterKeyID is the system_keys key_id holding the HMAC master used
	// to derive daily EntityID keys. Rotation regenerates this value, which
	// resets rate-limiting/correlation windows (a privacy improvement).
	EntityIDMasterKeyID = "entity_id_master_key"
	// EntityIDKeyType is the system_keys key_type (wrapping derivation context)
	// for the EntityID master.
	EntityIDKeyType = "entity_id"

	// ShareTicketMasterKeyID is the system_keys key_id holding the HMAC key
	// used to issue and verify short-lived share download tickets. A ticket
	// binds a recipient's entity ID to a share ID for a bounded TTL, replacing
	// the previous never-rotated static download token as the per-chunk
	// credential. Rotation regenerates this value, which simply invalidates
	// outstanding tickets (recipients re-issue on next envelope decrypt).
	ShareTicketMasterKeyID = "share_ticket_master_key"
	// ShareTicketKeyType is the system_keys key_type (wrapping derivation
	// context) for the share ticket master.
	ShareTicketKeyType = "share_ticket"
)

// EnvelopeRotationStats reports the outcome of a system_keys re-wrap.
type EnvelopeRotationStats struct {
	RowsRewrapped       int
	EntityIDRegenerated bool
}

// ReencryptAllSystemKeys re-wraps every system_keys row from oldMaster to
// newMaster in a single transaction. The EntityID master row is regenerated with
// fresh random material instead of being re-wrapped, so previously derived
// EntityIDs stop matching after the service restarts under the new master. If no
// EntityID master row exists yet (fresh deployment), nothing is created; the
// running service generates it lazily on next start.
func ReencryptAllSystemKeys(db *sql.DB, oldMaster, newMaster []byte) (EnvelopeRotationStats, error) {
	var stats EnvelopeRotationStats
	if len(oldMaster) != 32 || len(newMaster) != 32 {
		return stats, fmt.Errorf("envelope master keys must be 32 bytes")
	}

	tx, err := db.Begin()
	if err != nil {
		return stats, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT key_id, key_type, encrypted_data, nonce FROM system_keys`)
	if err != nil {
		return stats, fmt.Errorf("failed to list system_keys: %w", err)
	}

	// Buffer the re-wrapped rows before issuing UPDATEs so we never hold an open
	// result cursor and a write on the same connection at the same time.
	type rewrappedRow struct {
		keyID    string
		dataHex  string
		nonceHex string
	}
	var updates []rewrappedRow
	regenerated := false

	for rows.Next() {
		var keyID, keyType, encHex, nonceHex string
		if err := rows.Scan(&keyID, &keyType, &encHex, &nonceHex); err != nil {
			rows.Close()
			return stats, err
		}

		var plaintext []byte
		if keyID == EntityIDMasterKeyID || keyID == ShareTicketMasterKeyID {
			plaintext = make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
				rows.Close()
				return stats, fmt.Errorf("failed to generate new system key %s: %w", keyID, err)
			}
			regenerated = true
		} else {
			encData, derr := hex.DecodeString(encHex)
			if derr != nil {
				rows.Close()
				return stats, fmt.Errorf("failed to decode encrypted_data for %s: %w", keyID, derr)
			}
			nonce, derr := hex.DecodeString(nonceHex)
			if derr != nil {
				rows.Close()
				return stats, fmt.Errorf("failed to decode nonce for %s: %w", keyID, derr)
			}
			plaintext, derr = DecryptSystemKeyWithMaster(oldMaster, encData, nonce, keyType)
			if derr != nil {
				rows.Close()
				return stats, fmt.Errorf("failed to decrypt %s under old master: %w", keyID, derr)
			}
		}

		newData, newNonce, eerr := EncryptSystemKeyWithMaster(newMaster, plaintext, keyType)
		SecureClear(plaintext)
		if eerr != nil {
			rows.Close()
			return stats, fmt.Errorf("failed to re-encrypt %s under new master: %w", keyID, eerr)
		}

		updates = append(updates, rewrappedRow{
			keyID:    keyID,
			dataHex:  hex.EncodeToString(newData),
			nonceHex: hex.EncodeToString(newNonce),
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return stats, err
	}
	rows.Close()

	for _, u := range updates {
		if _, err := tx.Exec(
			`UPDATE system_keys SET encrypted_data = ?, nonce = ? WHERE key_id = ?`,
			u.dataHex, u.nonceHex, u.keyID,
		); err != nil {
			return stats, fmt.Errorf("failed to update system key %s: %w", u.keyID, err)
		}
		stats.RowsRewrapped++
	}

	if err := tx.Commit(); err != nil {
		return stats, fmt.Errorf("failed to commit system_keys re-encryption: %w", err)
	}

	stats.EntityIDRegenerated = regenerated
	return stats, nil
}

// VerifyAllSystemKeysDecryptable confirms every system_keys row can be decrypted
// under the given master. Used after a rotation swap to prove the entire table is
// readable before the service is restarted. system_keys is small, so a full
// verification is cheap and strictly safer than sampling a single row.
func VerifyAllSystemKeysDecryptable(db *sql.DB, master []byte) (int, error) {
	if len(master) != 32 {
		return 0, fmt.Errorf("envelope master key must be 32 bytes")
	}

	rows, err := db.Query(`SELECT key_id, key_type, encrypted_data, nonce FROM system_keys`)
	if err != nil {
		return 0, fmt.Errorf("failed to list system_keys for verification: %w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var keyID, keyType, encHex, nonceHex string
		if err := rows.Scan(&keyID, &keyType, &encHex, &nonceHex); err != nil {
			return count, err
		}
		encData, derr := hex.DecodeString(encHex)
		if derr != nil {
			return count, fmt.Errorf("verification: failed to decode encrypted_data for %s: %w", keyID, derr)
		}
		nonce, derr := hex.DecodeString(nonceHex)
		if derr != nil {
			return count, fmt.Errorf("verification: failed to decode nonce for %s: %w", keyID, derr)
		}
		plaintext, derr := DecryptSystemKeyWithMaster(master, encData, nonce, keyType)
		if derr != nil {
			return count, fmt.Errorf("verification decrypt failed for %s: %w", keyID, derr)
		}
		SecureClear(plaintext)
		count++
	}
	return count, rows.Err()
}
