package models

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/logging"
)

// ContactInfo represents the plaintext contact information structure
type ContactInfo struct {
	DisplayName string          `json:"display_name"`
	Contacts    []ContactMethod `json:"contacts"`
	Notes       string          `json:"notes"`
}

// ContactMethod represents a single contact method (email, signal, etc.)
type ContactMethod struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Label string `json:"label,omitempty"` // Only used when Type is "other"
}

// ValidContactTypes lists the allowed contact method types
var ValidContactTypes = map[string]bool{
	"email":    true,
	"sms":      true,
	"signal":   true,
	"whatsapp": true,
	"wechat":   true,
	"telegram": true,
	"matrix":   true,
	"other":    true,
}

// contactInfoKeyID is the system_keys identifier for the contact info encryption key
const contactInfoKeyID = "contact_info_encryption_key_v1"
const contactInfoKeyType = "contact_info"
const contactInfoKeySize = 32

// MaxContactInfoSize is the maximum size of the plaintext JSON blob (8 KB)
const MaxContactInfoSize = 8192

// MaxDisplayNameLength is the maximum length for the display name field
const MaxDisplayNameLength = 100

// MaxContactValue is the maximum length for a contact value
const MaxContactValue = 500

// MaxContactLabel is the maximum length for a custom contact label
const MaxContactLabel = 100

// MaxContacts is the maximum number of contact methods
const MaxContacts = 20

// MaxNotesLength is the maximum length for the notes field
const MaxNotesLength = 2000

// Validate checks that the contact info structure is well-formed
func (ci *ContactInfo) Validate() error {
	if ci.DisplayName == "" {
		return fmt.Errorf("display_name is required")
	}
	if len(ci.DisplayName) > MaxDisplayNameLength {
		return fmt.Errorf("display_name must be at most %d characters", MaxDisplayNameLength)
	}

	if len(ci.Contacts) > MaxContacts {
		return fmt.Errorf("at most %d contact methods allowed", MaxContacts)
	}

	for i, c := range ci.Contacts {
		if !ValidContactTypes[c.Type] {
			return fmt.Errorf("contact[%d]: invalid type '%s'", i, c.Type)
		}
		if c.Value == "" {
			return fmt.Errorf("contact[%d]: value is required", i)
		}
		if len(c.Value) > MaxContactValue {
			return fmt.Errorf("contact[%d]: value must be at most %d characters", i, MaxContactValue)
		}
		if c.Type == "other" && c.Label == "" {
			return fmt.Errorf("contact[%d]: label is required when type is 'other'", i)
		}
		if len(c.Label) > MaxContactLabel {
			return fmt.Errorf("contact[%d]: label must be at most %d characters", i, MaxContactLabel)
		}
		// Clear label for non-other types
		if c.Type != "other" {
			ci.Contacts[i].Label = ""
		}
	}

	if len(ci.Notes) > MaxNotesLength {
		return fmt.Errorf("notes must be at most %d characters", MaxNotesLength)
	}

	return nil
}

// getContactInfoKey retrieves or generates the contact info encryption key
func getContactInfoKey() ([]byte, error) {
	km, err := crypto.GetKeyManager()
	if err != nil {
		return nil, fmt.Errorf("failed to get KeyManager: %w", err)
	}
	key, err := km.GetOrGenerateKey(contactInfoKeyID, contactInfoKeyType, contactInfoKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to get contact info encryption key: %w", err)
	}
	return key, nil
}

// SaveContactInfo encrypts and stores contact info for a user
func SaveContactInfo(dbtx DBTX, username string, info *ContactInfo) error {
	// Validate
	if err := info.Validate(); err != nil {
		return fmt.Errorf("invalid contact info: %w", err)
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal contact info: %w", err)
	}

	// Check size limit
	if len(jsonBytes) > MaxContactInfoSize {
		return fmt.Errorf("contact info exceeds maximum size of %d bytes", MaxContactInfoSize)
	}

	// Get encryption key
	key, err := getContactInfoKey()
	if err != nil {
		return err
	}

	// Encrypt with AES-256-GCM (returns nonce + ciphertext + tag)
	encrypted, err := crypto.EncryptGCM(jsonBytes, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt contact info: %w", err)
	}

	// Split nonce from ciphertext for storage
	nonceSize := crypto.AesGcmNonceSize()
	if len(encrypted) < nonceSize {
		return fmt.Errorf("encrypted data too short")
	}
	nonce := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]

	// Store as base64
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	dataB64 := base64.StdEncoding.EncodeToString(ciphertext)

	// Upsert into database
	_, err = dbtx.Exec(
		`INSERT OR REPLACE INTO user_contact_info (username, encrypted_data, nonce, updated_at) VALUES (?, ?, ?, ?)`,
		username, dataB64, nonceB64, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("failed to store contact info: %w", err)
	}

	logging.InfoLogger.Printf("Contact info saved for user: %s", username)
	return nil
}

// GetContactInfo retrieves and decrypts contact info for a user
func GetContactInfo(dbtx DBTX, username string) (*ContactInfo, error) {
	var dataB64, nonceB64 string

	err := dbtx.QueryRow(
		`SELECT encrypted_data, nonce FROM user_contact_info WHERE username = ?`,
		username,
	).Scan(&dataB64, &nonceB64)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No contact info set
		}
		return nil, fmt.Errorf("failed to query contact info: %w", err)
	}

	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode contact info data: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode contact info nonce: %w", err)
	}

	// Get encryption key
	key, err := getContactInfoKey()
	if err != nil {
		return nil, err
	}

	// Reassemble nonce + ciphertext for decryption
	encrypted := append(nonce, ciphertext...)

	// Decrypt
	plaintext, err := crypto.DecryptGCM(encrypted, key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt contact info: %w", err)
	}

	// Unmarshal JSON
	var info ContactInfo
	if err := json.Unmarshal(plaintext, &info); err != nil {
		return nil, fmt.Errorf("failed to parse contact info: %w", err)
	}

	return &info, nil
}

// DeleteContactInfo removes contact info for a user
func DeleteContactInfo(dbtx DBTX, username string) error {
	result, err := dbtx.Exec(
		`DELETE FROM user_contact_info WHERE username = ?`,
		username,
	)
	if err != nil {
		return fmt.Errorf("failed to delete contact info: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("no contact info found for user")
	}

	logging.InfoLogger.Printf("Contact info deleted for user: %s", username)
	return nil
}

// HasContactInfo checks if a user has contact info set
func HasContactInfo(dbtx DBTX, username string) (bool, error) {
	var count int
	err := dbtx.QueryRow(
		`SELECT COUNT(*) FROM user_contact_info WHERE username = ?`,
		username,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check contact info: %w", err)
	}
	return count > 0, nil
}
