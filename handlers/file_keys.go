package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
	"github.com/84adam/arkfile/storage"
)

// FileKeyResponse represents a file encryption key
type FileKeyResponse struct {
	KeyID        string `json:"keyId"`
	KeyType      string `json:"keyType"`
	KeyLabel     string `json:"keyLabel"`
	PasswordHint string `json:"passwordHint"`
	IsPrimary    bool   `json:"isPrimary"`
	CreatedAt    string `json:"createdAt"`
}

// UpdateEncryption handles updating a file's encryption with a new or converted format
func UpdateEncryption(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	filename := c.Param("filename")

	// Check if the file exists and user owns it
	var ownerEmail string
	err := database.DB.QueryRow(
		"SELECT owner_email FROM file_metadata WHERE filename = ?",
		filename,
	).Scan(&ownerEmail)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error checking file ownership: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error checking file ownership")
	}

	if ownerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized to modify this file")
	}

	// Parse the request body
	var request struct {
		EncryptedData string `json:"encryptedData"`
		NewKeyID      string `json:"newKeyId"`
		KeyLabel      string `json:"keyLabel"`
		PasswordHint  string `json:"passwordHint"`
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Begin transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()

	// Update the file in object storage
	objectName := filename
	reader := strings.NewReader(request.EncryptedData)
	contentType := "application/octet-stream"

	// Upload the updated encrypted file using storage.Provider
	_, err = storage.Provider.PutObject(
		c.Request().Context(),
		objectName, // bucketName is handled by the provider
		reader,
		int64(len(request.EncryptedData)),
		minio.PutObjectOptions{ContentType: contentType},
	)

	if err != nil {
		logging.ErrorLogger.Printf("Failed to update file in storage: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update file in storage")
	}

	// Update file metadata to indicate multi-key
	_, err = tx.Exec(
		"UPDATE file_metadata SET multi_key = TRUE WHERE filename = ?",
		filename,
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to update file metadata: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update file metadata")
	}

	// Determine if this is a new key or conversion from single to multi-key
	var existingKeyCount int
	err = tx.QueryRow(
		"SELECT COUNT(*) FROM file_encryption_keys WHERE file_id = ?",
		filename,
	).Scan(&existingKeyCount)
	if err != nil {
		logging.ErrorLogger.Printf("Error checking existing keys: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error checking existing keys")
	}

	// If first key, add account key as primary
	if existingKeyCount == 0 {
		_, err = tx.Exec(
			"INSERT INTO file_encryption_keys (file_id, key_id, key_type, key_label, is_primary) VALUES (?, ?, ?, ?, ?)",
			filename, "primary", "account", "Account Password", true,
		)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to add primary key: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to add primary key")
		}
	}

	// Add the new custom key
	_, err = tx.Exec(
		"INSERT INTO file_encryption_keys (file_id, key_id, key_type, key_label, password_hint, is_primary) VALUES (?, ?, ?, ?, ?, ?)",
		filename, request.NewKeyID, "custom", request.KeyLabel, request.PasswordHint, false,
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to add new key: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to add new encryption key")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Failed to commit transaction: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to complete encryption update")
	}

	logging.InfoLogger.Printf("File encryption updated: %s by %s", filename, email)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "File encryption updated successfully",
		"keyId":   request.NewKeyID,
	})
}

// ListKeys lists all encryption keys for a file
func ListKeys(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	filename := c.Param("filename")

	// Check if the file exists and user owns it
	var ownerEmail string
	err := database.DB.QueryRow(
		"SELECT owner_email FROM file_metadata WHERE filename = ?",
		filename,
	).Scan(&ownerEmail)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error checking file ownership: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error checking file ownership")
	}

	if ownerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized to access this file's keys")
	}

	// Query all keys for this file
	rows, err := database.DB.Query(`
		SELECT key_id, key_type, key_label, password_hint, is_primary, created_at 
		FROM file_encryption_keys 
		WHERE file_id = ? 
		ORDER BY is_primary DESC, created_at ASC
	`, filename)

	if err != nil {
		logging.ErrorLogger.Printf("Error querying file keys: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error retrieving file keys")
	}
	defer rows.Close()

	var keys []FileKeyResponse
	for rows.Next() {
		var key FileKeyResponse
		var createdAt string
		err := rows.Scan(&key.KeyID, &key.KeyType, &key.KeyLabel, &key.PasswordHint, &key.IsPrimary, &createdAt)
		if err != nil {
			logging.ErrorLogger.Printf("Error scanning key row: %v", err)
			continue
		}

		key.CreatedAt = createdAt
		keys = append(keys, key)
	}

	if err = rows.Err(); err != nil {
		logging.ErrorLogger.Printf("Error iterating key rows: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error processing file keys")
	}

	// Check if file is multi-key encrypted
	var isMultiKey bool
	err = database.DB.QueryRow(
		"SELECT multi_key FROM file_metadata WHERE filename = ?",
		filename,
	).Scan(&isMultiKey)

	if err != nil && err != sql.ErrNoRows {
		logging.ErrorLogger.Printf("Error checking multi-key status: %v", err)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"keys":       keys,
		"isMultiKey": isMultiKey,
	})
}

// DeleteKey removes an encryption key from a file
func DeleteKey(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	filename := c.Param("filename")
	keyID := c.Param("keyId")

	// Check if the file exists and user owns it
	var ownerEmail string
	err := database.DB.QueryRow(
		"SELECT owner_email FROM file_metadata WHERE filename = ?",
		filename,
	).Scan(&ownerEmail)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error checking file ownership: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error checking file ownership")
	}

	if ownerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized to modify this file's keys")
	}

	// Check if this is a primary key (cannot be deleted)
	var isPrimary bool
	err = database.DB.QueryRow(
		"SELECT is_primary FROM file_encryption_keys WHERE file_id = ? AND key_id = ?",
		filename, keyID,
	).Scan(&isPrimary)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Key not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Error checking key status: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error checking key status")
	}

	if isPrimary {
		return echo.NewHTTPError(http.StatusBadRequest, "Cannot delete the primary key")
	}

	// Count remaining keys to ensure at least one will remain
	var keyCount int
	err = database.DB.QueryRow(
		"SELECT COUNT(*) FROM file_encryption_keys WHERE file_id = ?",
		filename,
	).Scan(&keyCount)

	if err != nil {
		logging.ErrorLogger.Printf("Error counting keys: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error counting keys")
	}

	if keyCount <= 1 {
		return echo.NewHTTPError(http.StatusBadRequest, "Cannot delete the only key for a file")
	}

	// Delete the key
	_, err = database.DB.Exec(
		"DELETE FROM file_encryption_keys WHERE file_id = ? AND key_id = ?",
		filename, keyID,
	)

	if err != nil {
		logging.ErrorLogger.Printf("Error deleting key: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error deleting key")
	}

	logging.InfoLogger.Printf("Key deleted: %s for file %s by %s", keyID, filename, email)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Key deleted successfully",
	})
}

// UpdateKey updates a key's label or password hint
func UpdateKey(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	filename := c.Param("filename")
	keyID := c.Param("keyId")

	// Check if the file exists and user owns it
	var ownerEmail string
	err := database.DB.QueryRow(
		"SELECT owner_email FROM file_metadata WHERE filename = ?",
		filename,
	).Scan(&ownerEmail)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error checking file ownership: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error checking file ownership")
	}

	if ownerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized to modify this file's keys")
	}

	// Parse request
	var request struct {
		KeyLabel     string `json:"keyLabel"`
		PasswordHint string `json:"passwordHint"`
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Update key details
	_, err = database.DB.Exec(
		"UPDATE file_encryption_keys SET key_label = ?, password_hint = ? WHERE file_id = ? AND key_id = ?",
		request.KeyLabel, request.PasswordHint, filename, keyID,
	)

	if err != nil {
		logging.ErrorLogger.Printf("Error updating key: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error updating key")
	}

	logging.InfoLogger.Printf("Key updated: %s for file %s by %s", keyID, filename, email)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Key updated successfully",
	})
}

// SetPrimaryKey sets a key as the primary key for a file
func SetPrimaryKey(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	filename := c.Param("filename")
	keyID := c.Param("keyId")

	// Check if the file exists and user owns it
	var ownerEmail string
	err := database.DB.QueryRow(
		"SELECT owner_email FROM file_metadata WHERE filename = ?",
		filename,
	).Scan(&ownerEmail)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error checking file ownership: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error checking file ownership")
	}

	if ownerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized to modify this file's keys")
	}

	// Begin transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()

	// Reset all keys to non-primary
	_, err = tx.Exec(
		"UPDATE file_encryption_keys SET is_primary = FALSE WHERE file_id = ?",
		filename,
	)

	if err != nil {
		logging.ErrorLogger.Printf("Error resetting primary keys: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error updating keys")
	}

	// Set the specified key as primary
	result, err := tx.Exec(
		"UPDATE file_encryption_keys SET is_primary = TRUE WHERE file_id = ? AND key_id = ?",
		filename, keyID,
	)

	if err != nil {
		logging.ErrorLogger.Printf("Error setting primary key: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error updating primary key")
	}

	// Check if key exists
	rows, err := result.RowsAffected()
	if err != nil {
		logging.ErrorLogger.Printf("Error checking rows affected: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error checking database result")
	}

	if rows == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "Key not found")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Failed to commit transaction: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to complete primary key update")
	}

	logging.InfoLogger.Printf("Primary key set: %s for file %s by %s", keyID, filename, email)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Primary key updated successfully",
	})
}

// RegisterCustomFilePassword registers a custom password with OPAQUE for a file
func RegisterCustomFilePassword(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	filename := c.Param("filename")

	// Check file ownership
	var ownerEmail string
	err := database.DB.QueryRow(
		"SELECT owner_email FROM file_metadata WHERE filename = ?",
		filename,
	).Scan(&ownerEmail)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Database error")
	}

	if ownerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized to modify this file")
	}

	var request struct {
		Password     string `json:"password"`
		KeyLabel     string `json:"keyLabel"`
		PasswordHint string `json:"passwordHint"`
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// Get user object and use integrated OPAQUE method
	user, err := models.GetUserByEmail(database.DB, email)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "User not found")
	}

	// Register custom password using User model integration
	err = user.RegisterFilePassword(database.DB, filename, request.Password, request.KeyLabel, request.PasswordHint)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to register custom file password: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to register custom password")
	}

	logging.InfoLogger.Printf("Custom file password registered for %s by %s", filename, email)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Custom file password registered successfully",
		"keyType": "custom",
	})
}

// GetFileDecryptionKey provides the encryption key for a file given a password
func GetFileDecryptionKey(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	filename := c.Param("filename")

	// Check file ownership
	var ownerEmail string
	err := database.DB.QueryRow(
		"SELECT owner_email FROM file_metadata WHERE filename = ?",
		filename,
	).Scan(&ownerEmail)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Database error")
	}

	if ownerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Access denied")
	}

	var request struct {
		Password string `json:"password"`
		KeyType  string `json:"keyType"` // 'account' or 'custom'
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	var encryptionKey []byte

	switch request.KeyType {
	case "account":
		// Authenticate user's account password via existing OPAQUE system
		accountExportKey, err := auth.AuthenticateUser(database.DB, email, request.Password)
		if err != nil {
			logging.ErrorLogger.Printf("Account authentication failed: %v", err)
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid account password")
		}
		defer secureZeroBytes(accountExportKey)

		// Derive file-specific encryption key from account export key
		encryptionKey, err = deriveAccountFileKey(accountExportKey, email, filename)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Key derivation failed")
		}

	case "custom":
		// Get user object and use integrated OPAQUE method
		user, err := models.GetUserByEmail(database.DB, email)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "User not found")
		}

		// Authenticate custom password using User model integration
		exportKey, err := user.AuthenticateFilePassword(database.DB, filename, request.Password)
		if err != nil {
			logging.ErrorLogger.Printf("Custom password authentication failed: %v", err)
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid custom password")
		}
		defer secureZeroBytes(exportKey)

		// Derive file encryption key from custom password export key
		encryptionKey, err = deriveOPAQUEFileKey(exportKey, filename, email)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Key derivation failed")
		}

	default:
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid key type")
	}

	defer secureZeroBytes(encryptionKey)

	// Return key as hex for client-side decryption
	keyHex := fmt.Sprintf("%x", encryptionKey)

	logging.InfoLogger.Printf("File decryption key provided: %s (%s) for %s", filename, request.KeyType, email)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"encryptionKey": keyHex,
		"keyType":       request.KeyType,
	})
}

// Helper functions for OPAQUE integration
func secureZeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func deriveAccountFileKey(exportKey []byte, userEmail, fileID string) ([]byte, error) {
	// This would use HKDF with proper domain separation
	// Placeholder implementation - should use crypto.DeriveAccountFileKey
	return make([]byte, 32), nil
}

func deriveOPAQUEFileKey(exportKey []byte, fileID, userEmail string) ([]byte, error) {
	// This would use HKDF with proper domain separation
	// Placeholder implementation - should use crypto.DeriveOPAQUEFileKey
	return make([]byte, 32), nil
}
