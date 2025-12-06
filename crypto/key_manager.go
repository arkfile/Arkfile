package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// KeyManager handles the lifecycle of system secrets using Envelope Encryption.
type KeyManager struct {
	masterKey []byte
	db        *sql.DB
}

var (
	globalKeyManager *KeyManager
	onceKeyManager   sync.Once
)

// InitKeyManager initializes the global KeyManager.
// It expects ARKFILE_MASTER_KEY to be set in the environment.
func InitKeyManager(db *sql.DB) error {
	var err error
	onceKeyManager.Do(func() {
		masterKeyHex := os.Getenv("ARKFILE_MASTER_KEY")
		if masterKeyHex == "" {
			err = fmt.Errorf("ARKFILE_MASTER_KEY environment variable is not set")
			return
		}

		masterKey, decodeErr := hex.DecodeString(masterKeyHex)
		if decodeErr != nil {
			err = fmt.Errorf("failed to decode ARKFILE_MASTER_KEY: %w", decodeErr)
			return
		}

		if len(masterKey) != 32 {
			err = fmt.Errorf("ARKFILE_MASTER_KEY must be 32 bytes (64 hex chars), got %d bytes", len(masterKey))
			return
		}

		globalKeyManager = &KeyManager{
			masterKey: masterKey,
			db:        db,
		}
	})

	// If initialization failed (either now or in a previous call), return error
	if globalKeyManager == nil {
		if err != nil {
			return err
		}
		return fmt.Errorf("KeyManager initialization failed in a previous call")
	}

	return nil
}

// GetKeyManager returns the global KeyManager instance.
func GetKeyManager() (*KeyManager, error) {
	if globalKeyManager == nil {
		return nil, fmt.Errorf("KeyManager not initialized")
	}
	return globalKeyManager, nil
}

// deriveWrappingKey derives a specific wrapping key from the Master Key using HKDF.
func (km *KeyManager) deriveWrappingKey(keyType string) ([]byte, error) {
	info := []byte(fmt.Sprintf("ARKFILE_%s_KEY_ENCRYPTION", keyType))
	reader := hkdf.Expand(sha256.New, km.masterKey, info)

	wrappingKey := make([]byte, 32)
	if _, err := io.ReadFull(reader, wrappingKey); err != nil {
		return nil, fmt.Errorf("failed to derive wrapping key for %s: %w", keyType, err)
	}
	return wrappingKey, nil
}

// EncryptSystemKey encrypts a raw key using the Master Key (via a derived wrapping key).
func (km *KeyManager) EncryptSystemKey(rawKey []byte, keyType string) ([]byte, []byte, error) {
	wrappingKey, err := km.deriveWrappingKey(keyType)
	if err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	encryptedKey := gcm.Seal(nil, nonce, rawKey, nil)
	return encryptedKey, nonce, nil
}

// DecryptSystemKey decrypts an encrypted key using the Master Key.
func (km *KeyManager) DecryptSystemKey(encryptedKey, nonce []byte, keyType string) ([]byte, error) {
	wrappingKey, err := km.deriveWrappingKey(keyType)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	return plaintext, nil
}

// GetOrGenerateKey retrieves a key from the DB or generates/stores it if missing.
// This function is safe for concurrent access across multiple instances. It uses
// database transactions to ensure only one instance generates a key during initial
// deployment, preventing race conditions in multi-instance scenarios.
//
// keyID: Unique identifier for the key (e.g., "jwt_signing_key_v1")
// keyType: Type of key for derivation context (e.g., "jwt", "totp")
// keySize: Size of key to generate if missing
func (km *KeyManager) GetOrGenerateKey(keyID string, keyType string, keySize int) ([]byte, error) {
	// 1. Try to fetch from DB (fast path, no lock needed)
	var encryptedData, nonce []byte
	err := km.db.QueryRow("SELECT encrypted_data, nonce FROM system_keys WHERE key_id = ?", keyID).Scan(&encryptedData, &nonce)

	if err == nil {
		// Key found, decrypt and return it
		return km.DecryptSystemKey(encryptedData, nonce, keyType)
	} else if err != sql.ErrNoRows {
		// Database error
		return nil, fmt.Errorf("failed to query system_keys: %w", err)
	}

	// 2. Key not found - use transaction to acquire exclusive lock
	// This prevents multiple instances from generating different keys simultaneously
	tx, err := km.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// 3. Check again within transaction (another instance may have created it while we waited)
	err = tx.QueryRow("SELECT encrypted_data, nonce FROM system_keys WHERE key_id = ?", keyID).Scan(&encryptedData, &nonce)
	if err == nil {
		// Key was created by another instance while we waited for the lock
		tx.Rollback()
		return km.DecryptSystemKey(encryptedData, nonce, keyType)
	} else if err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to query system_keys in transaction: %w", err)
	}

	// 4. We have the lock and key still doesn't exist - generate it
	rawKey := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, rawKey); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	// 5. Encrypt the key
	encryptedData, nonce, err = km.EncryptSystemKey(rawKey, keyType)
	if err != nil {
		return nil, err
	}

	// 6. Insert the key within the transaction
	_, err = tx.Exec(
		"INSERT INTO system_keys (key_id, key_type, encrypted_data, nonce) VALUES (?, ?, ?, ?)",
		keyID, keyType, encryptedData, nonce,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert key: %w", err)
	}

	// 7. Commit transaction (releases lock)
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return rawKey, nil
}

// StoreKey encrypts and stores a key in the database.
// It overwrites any existing key with the same ID.
func (km *KeyManager) StoreKey(keyID string, keyType string, rawKey []byte) error {
	encryptedData, nonce, err := km.EncryptSystemKey(rawKey, keyType)
	if err != nil {
		return err
	}

	// Use UPSERT logic (SQLite specific syntax, but standard SQL usually requires checking existence or ON CONFLICT)
	// Since we're using standard SQL driver, we'll use REPLACE INTO which works for SQLite
	_, err = km.db.Exec(
		"REPLACE INTO system_keys (key_id, key_type, encrypted_data, nonce) VALUES (?, ?, ?, ?)",
		keyID, keyType, encryptedData, nonce,
	)
	if err != nil {
		return fmt.Errorf("failed to store system key: %w", err)
	}

	return nil
}

// GetKey retrieves and decrypts a key from the database.
// Returns error if key not found.
func (km *KeyManager) GetKey(keyID string, keyType string) ([]byte, error) {
	var encryptedData, nonce []byte
	err := km.db.QueryRow("SELECT encrypted_data, nonce FROM system_keys WHERE key_id = ?", keyID).Scan(&encryptedData, &nonce)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("key not found: %s", keyID)
		}
		return nil, fmt.Errorf("failed to query system_keys: %w", err)
	}

	return km.DecryptSystemKey(encryptedData, nonce, keyType)
}

// DeleteKey removes a key from the database.
func (km *KeyManager) DeleteKey(keyID string) error {
	_, err := km.db.Exec("DELETE FROM system_keys WHERE key_id = ?", keyID)
	if err != nil {
		return fmt.Errorf("failed to delete system key: %w", err)
	}
	return nil
}
