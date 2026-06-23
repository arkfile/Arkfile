package auth

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/84adam/Arkfile/logging"
	"github.com/google/uuid"
)

// MFACredentialRow is stored MFA state for one enrolled or pending method.
type MFACredentialRow struct {
	CredentialID    string
	Username        string
	MethodType      string
	CredentialData  []byte
	Enabled         bool
	SetupCompleted  bool
	CreatedAt       time.Time
	LastUsed        *time.Time
}

// MFALoginMethod describes one completed factor available at login.
type MFALoginMethod struct {
	Type         string `json:"type"`
	CredentialID string `json:"credential_id,omitempty"`
	Label        string `json:"label,omitempty"`
}

// MFACredentialSummary is non-secret metadata returned to the credential owner.
type MFACredentialSummary struct {
	CredentialID string     `json:"credential_id"`
	MethodType   string     `json:"method_type"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsed     *time.Time `json:"last_used,omitempty"`
	Label        string     `json:"label,omitempty"`
}

// AdminMFACredentialSummary is non-secret metadata for admin operations (no user labels).
type AdminMFACredentialSummary struct {
	CredentialID string    `json:"credential_id"`
	MethodType   string    `json:"method_type"`
	CreatedAt    time.Time `json:"created_at"`
}

func newCredentialID() string {
	return uuid.NewString()
}

// HasCompletedMFA reports whether the user has at least one completed MFA credential.
func HasCompletedMFA(db *sql.DB, username string) (bool, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM user_mfa_credentials
		WHERE username = ? AND enabled = 1 AND setup_completed = 1`,
		username,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check MFA completion: %w", err)
	}
	return count > 0, nil
}

// IsUserMFAEnabled is an alias for HasCompletedMFA.
func IsUserMFAEnabled(db *sql.DB, username string) (bool, error) {
	return HasCompletedMFA(db, username)
}

// CountCompletedMethods returns the number of completed MFA credentials for a user.
func CountCompletedMethods(db *sql.DB, username string) (int, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM user_mfa_credentials
		WHERE username = ? AND enabled = 1 AND setup_completed = 1`,
		username,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count completed MFA methods: %w", err)
	}
	return count, nil
}

// HasMethodRow reports whether any credential row exists for the method type.
func HasMethodRow(db *sql.DB, username, methodType string) (bool, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM user_mfa_credentials
		WHERE username = ? AND method_type = ?`,
		username, methodType,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// HasCompletedMethodType reports whether the user has a completed credential of the given type.
func HasCompletedMethodType(db *sql.DB, username, methodType string) (bool, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM user_mfa_credentials
		WHERE username = ? AND method_type = ? AND enabled = 1 AND setup_completed = 1`,
		username, methodType,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func scanCredentialRow(rows *sql.Rows) (MFACredentialRow, error) {
	var row MFACredentialRow
	var createdAtStr string
	var lastUsedStr sql.NullString
	if err := rows.Scan(
		&row.CredentialID,
		&row.Username,
		&row.MethodType,
		&row.CredentialData,
		&row.Enabled,
		&row.SetupCompleted,
		&createdAtStr,
		&lastUsedStr,
	); err != nil {
		return row, err
	}
	row.CreatedAt = parseMFATimestamp(createdAtStr)
	if lastUsedStr.Valid && lastUsedStr.String != "" {
		t := parseMFATimestamp(lastUsedStr.String)
		row.LastUsed = &t
	}
	if decoded, err := decodeBase64IfNeeded(row.CredentialData); err == nil {
		row.CredentialData = decoded
	}
	return row, nil
}

func parseMFATimestamp(raw string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t
		}
	}
	return time.Time{}
}

// GetCredentialByMethod loads one credential row by username and method type.
func GetCredentialByMethod(db *sql.DB, username, methodType string) (*MFACredentialRow, error) {
	row := &MFACredentialRow{}
	var createdAtStr string
	var lastUsedStr sql.NullString
	err := db.QueryRow(`
		SELECT credential_id, username, method_type, credential_data,
		       enabled, setup_completed, created_at, last_used
		FROM user_mfa_credentials
		WHERE username = ? AND method_type = ?`,
		username, methodType,
	).Scan(
		&row.CredentialID,
		&row.Username,
		&row.MethodType,
		&row.CredentialData,
		&row.Enabled,
		&row.SetupCompleted,
		&createdAtStr,
		&lastUsedStr,
	)
	if err != nil {
		return nil, err
	}
	row.CreatedAt = parseMFATimestamp(createdAtStr)
	if lastUsedStr.Valid && lastUsedStr.String != "" {
		t := parseMFATimestamp(lastUsedStr.String)
		row.LastUsed = &t
	}
	if decoded, err := decodeBase64IfNeeded(row.CredentialData); err == nil {
		row.CredentialData = decoded
	}
	return row, nil
}

// GetCredentialByID loads one credential row owned by username.
func GetCredentialByID(db *sql.DB, username, credentialID string) (*MFACredentialRow, error) {
	row := &MFACredentialRow{}
	var createdAtStr string
	var lastUsedStr sql.NullString
	err := db.QueryRow(`
		SELECT credential_id, username, method_type, credential_data,
		       enabled, setup_completed, created_at, last_used
		FROM user_mfa_credentials
		WHERE username = ? AND credential_id = ?`,
		username, credentialID,
	).Scan(
		&row.CredentialID,
		&row.Username,
		&row.MethodType,
		&row.CredentialData,
		&row.Enabled,
		&row.SetupCompleted,
		&createdAtStr,
		&lastUsedStr,
	)
	if err != nil {
		return nil, err
	}
	row.CreatedAt = parseMFATimestamp(createdAtStr)
	if lastUsedStr.Valid && lastUsedStr.String != "" {
		t := parseMFATimestamp(lastUsedStr.String)
		row.LastUsed = &t
	}
	if decoded, err := decodeBase64IfNeeded(row.CredentialData); err == nil {
		row.CredentialData = decoded
	}
	return row, nil
}

// ListCompletedLoginMethods returns completed factors for the login picker.
func ListCompletedLoginMethods(db *sql.DB, username string) ([]MFALoginMethod, error) {
	rows, err := db.Query(`
		SELECT credential_id, method_type, credential_data
		FROM user_mfa_credentials
		WHERE username = ? AND enabled = 1 AND setup_completed = 1
		ORDER BY created_at ASC`,
		username,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list login MFA methods: %w", err)
	}
	defer rows.Close()

	var methods []MFALoginMethod
	for rows.Next() {
		var credentialID, methodType string
		var credentialData []byte
		if err := rows.Scan(&credentialID, &methodType, &credentialData); err != nil {
			return nil, err
		}
		if decoded, err := decodeBase64IfNeeded(credentialData); err == nil {
			credentialData = decoded
		}
		method := MFALoginMethod{Type: methodType, CredentialID: credentialID}
		if methodType == MFAMethodWebAuthn {
			if label, err := extractWebAuthnUserLabel(username, credentialData); err == nil {
				method.Label = label
			}
		}
		methods = append(methods, method)
	}
	return methods, rows.Err()
}

// ListUserCredentialSummaries returns owner-visible credential metadata.
func ListUserCredentialSummaries(db *sql.DB, username string) ([]MFACredentialSummary, error) {
	rows, err := db.Query(`
		SELECT credential_id, method_type, credential_data, created_at, last_used
		FROM user_mfa_credentials
		WHERE username = ? AND setup_completed = 1
		ORDER BY created_at ASC`,
		username,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list MFA credentials: %w", err)
	}
	defer rows.Close()

	var out []MFACredentialSummary
	for rows.Next() {
		var summary MFACredentialSummary
		var credentialData []byte
		var createdAtStr string
		var lastUsedStr sql.NullString
		if err := rows.Scan(&summary.CredentialID, &summary.MethodType, &credentialData, &createdAtStr, &lastUsedStr); err != nil {
			return nil, err
		}
		summary.CreatedAt = parseMFATimestamp(createdAtStr)
		if lastUsedStr.Valid && lastUsedStr.String != "" {
			t := parseMFATimestamp(lastUsedStr.String)
			summary.LastUsed = &t
		}
		if decoded, err := decodeBase64IfNeeded(credentialData); err == nil {
			credentialData = decoded
		}
		if summary.MethodType == MFAMethodWebAuthn {
			if label, err := extractWebAuthnUserLabel(username, credentialData); err == nil {
				summary.Label = label
			}
		}
		out = append(out, summary)
	}
	return out, rows.Err()
}

// ListAdminCredentialSummaries returns admin-visible metadata without user labels.
func ListAdminCredentialSummaries(db *sql.DB, username string) ([]AdminMFACredentialSummary, error) {
	rows, err := db.Query(`
		SELECT credential_id, method_type, created_at
		FROM user_mfa_credentials
		WHERE username = ? AND setup_completed = 1
		ORDER BY created_at ASC`,
		username,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list admin MFA credentials: %w", err)
	}
	defer rows.Close()

	var out []AdminMFACredentialSummary
	for rows.Next() {
		var summary AdminMFACredentialSummary
		var createdAtStr string
		if err := rows.Scan(&summary.CredentialID, &summary.MethodType, &createdAtStr); err != nil {
			return nil, err
		}
		summary.CreatedAt = parseMFATimestamp(createdAtStr)
		out = append(out, summary)
	}
	return out, rows.Err()
}

// DeleteCredential removes one MFA credential row for a user.
func DeleteCredential(db *sql.DB, username, credentialID string) error {
	res, err := db.Exec(`
		DELETE FROM user_mfa_credentials
		WHERE username = ? AND credential_id = ?`,
		username, credentialID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete MFA credential: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// AdminDeleteCredential removes one credential row during admin scoped reset.
func AdminDeleteCredential(db *sql.DB, targetUsername, credentialID string) error {
	return DeleteCredential(db, targetUsername, credentialID)
}

func getMFADataByMethod(db *sql.DB, username, methodType string) (*MFAData, error) {
	row, err := GetCredentialByMethod(db, username, methodType)
	if err != nil {
		return nil, err
	}
	return &MFAData{
		CredentialID:    row.CredentialID,
		MethodType:      row.MethodType,
		SecretEncrypted: row.CredentialData,
		Enabled:         row.Enabled,
		SetupCompleted:  row.SetupCompleted,
		CreatedAt:       row.CreatedAt,
		LastUsed:        row.LastUsed,
	}, nil
}

func getMFAData(db *sql.DB, username string) (*MFAData, error) {
	if row, err := GetCredentialByMethod(db, username, MFAMethodTOTP); err == nil {
		return mfaDataFromRow(row), nil
	} else if err != sql.ErrNoRows {
		return nil, err
	}
	row, err := GetCredentialByMethod(db, username, MFAMethodWebAuthn)
	if err != nil {
		return nil, err
	}
	return mfaDataFromRow(row), nil
}

func mfaDataFromRow(row *MFACredentialRow) *MFAData {
	return &MFAData{
		CredentialID:    row.CredentialID,
		MethodType:      row.MethodType,
		SecretEncrypted: row.CredentialData,
		Enabled:         row.Enabled,
		SetupCompleted:  row.SetupCompleted,
		CreatedAt:       row.CreatedAt,
		LastUsed:        row.LastUsed,
	}
}

func updateCredentialLastUsed(db *sql.DB, username, credentialID string) {
	_, err := db.Exec(`
		UPDATE user_mfa_credentials SET last_used = ? WHERE username = ? AND credential_id = ?`,
		time.Now().UTC(), username, credentialID,
	)
	if err != nil && logging.ErrorLogger != nil {
		logging.ErrorLogger.Printf("Failed to update MFA last_used: %v", err)
	}
}

func updateMethodLastUsed(db *sql.DB, username, methodType string) {
	_, err := db.Exec(`
		UPDATE user_mfa_credentials SET last_used = ? WHERE username = ? AND method_type = ?`,
		time.Now().UTC(), username, methodType,
	)
	if err != nil && logging.ErrorLogger != nil {
		logging.ErrorLogger.Printf("Failed to update MFA last_used: %v", err)
	}
}
