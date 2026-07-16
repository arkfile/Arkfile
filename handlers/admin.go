package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
	"github.com/arkfile/Arkfile/monitoring"
	"github.com/arkfile/Arkfile/storage"
)

// AdminCleanupRequest represents the request payload for test user cleanup
type AdminCleanupRequest struct {
	Username string `json:"username" validate:"required"`
	Confirm  bool   `json:"confirm" validate:"required"`
}

// AdminCleanupResponse represents the response from test user cleanup
type AdminCleanupResponse struct {
	Success       bool                   `json:"success"`
	TablesCleared map[string]int         `json:"tables_cleaned"`
	TotalRows     int                    `json:"total_rows_affected"`
	Details       map[string]interface{} `json:"details,omitempty"`
}

// AdminApproveRequest represents the request payload for user approval
type AdminApproveRequest struct {
	ApprovedBy        string `json:"approved_by" validate:"required"`
	StorageLimitBytes *int64 `json:"storage_limit_bytes,omitempty"`
}

// AdminApproveResponse represents the response from user approval
type AdminApproveResponse struct {
	Success    bool      `json:"success"`
	Username   string    `json:"username"`
	IsApproved bool      `json:"is_approved"`
	ApprovedBy string    `json:"approved_by"`
	ApprovedAt time.Time `json:"approved_at"`
}

// AdminUserStatusResponse represents the comprehensive user status response
type AdminUserStatusResponse struct {
	Exists   bool                   `json:"exists"`
	Username string                 `json:"username,omitempty"`
	User     *AdminUserInfo         `json:"user,omitempty"`
	MFA      *AdminMFAStatus       `json:"mfa,omitempty"`
	OPAQUE   *AdminOPAQUEStatus     `json:"opaque,omitempty"`
	Tokens   *AdminTokenStatus      `json:"tokens,omitempty"`
	Billing  *AdminBillingStatus    `json:"billing,omitempty"`
	Details  map[string]interface{} `json:"details,omitempty"`
}

// AdminUserInfo represents basic user information
type AdminUserInfo struct {
	ID         int64     `json:"id"`
	Username   string    `json:"username"`
	IsApproved bool      `json:"is_approved"`
	IsAdmin    bool      `json:"is_admin"`
	CreatedAt  time.Time `json:"created_at"`
}

// AdminMFAStatus represents TOTP status information
type AdminMFAStatus struct {
	Present        bool `json:"present"`
	Decryptable    bool `json:"decryptable"`
	Enabled        bool `json:"enabled"`
	SetupCompleted bool `json:"setup_completed"`
}

// AdminOPAQUEStatus represents OPAQUE status information
type AdminOPAQUEStatus struct {
	HasAccount   bool `json:"has_account"`
	RecordsCount int  `json:"records_count"`
}

// AdminTokenStatus represents token status information
type AdminTokenStatus struct {
	ActiveRefreshTokens int `json:"active_refresh_tokens"`
	RevokedTokens       int `json:"revoked_tokens"`
}

// AdminBillingStatus is the per-user billing snapshot surfaced in
// /api/admin/users/:username/status. Balances are signed microcents.
type AdminBillingStatus struct {
	BalanceUSDMicrocents         int64      `json:"balance_usd_microcents"`
	FormattedBalance             string     `json:"formatted_balance"`
	BillableBytes                int64      `json:"billable_bytes"`
	CurrentCostPerMonthUSDApprox string     `json:"current_cost_per_month_usd_approx"`
	LastBilledAt                 *time.Time `json:"last_billed_at,omitempty"`
}

// AdminCleanupTestUser performs comprehensive cleanup of test user data
func AdminCleanupTestUser(c echo.Context) error {
	// Parse request
	var req AdminCleanupRequest
	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}

	// Validate request
	if req.Username == "" {
		return JSONError(c, http.StatusBadRequest, "Username is required")
	}

	if !req.Confirm {
		return JSONError(c, http.StatusBadRequest, "Confirmation is required for cleanup operation")
	}

	// Get admin username for audit logging
	adminUsername := auth.GetUsernameFromToken(c)

	// Perform cleanup in a transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to start cleanup transaction")
	}
	defer tx.Rollback()

	tablesCleared := make(map[string]int)
	totalRows := 0

	// Cleanup operations with proper error handling
	cleanupOperations := []struct {
		table string
		query string
	}{
		{"users", "DELETE FROM users WHERE username = ?"},
		{"opaque_user_data", "DELETE FROM opaque_user_data WHERE username = ?"},
		{"user_mfa_credentials", "DELETE FROM user_mfa_credentials WHERE username = ?"},
		{"user_mfa_lockout", "DELETE FROM user_mfa_lockout WHERE username = ?"},
		{"user_mfa_backup_codes", "DELETE FROM user_mfa_backup_codes WHERE username = ?"},
		{"refresh_tokens", "DELETE FROM refresh_tokens WHERE username = ?"},
		{"mfa_usage_log", "DELETE FROM mfa_usage_log WHERE username = ?"},
		{"mfa_backup_usage", "DELETE FROM mfa_backup_usage WHERE username = ?"},
		{"revoked_tokens", "DELETE FROM revoked_tokens WHERE username = ?"},
		{"user_activity", "DELETE FROM user_activity WHERE username = ?"},
	}

	for _, op := range cleanupOperations {
		result, err := tx.Exec(op.query, req.Username)

		if err != nil {
			// Log error but continue with other tables
			logging.ErrorLogger.Printf("Admin cleanup failed for table %s: %v", op.table, err)
			tablesCleared[op.table] = 0
		} else {
			rowsAffected, _ := result.RowsAffected()
			rowsAffectedInt := int(rowsAffected)
			tablesCleared[op.table] = rowsAffectedInt
			totalRows += rowsAffectedInt
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Admin cleanup transaction commit failed: %v", err)
		return JSONError(c, http.StatusInternalServerError, "Failed to complete cleanup operation")
	}

	// Log admin action for audit trail
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":           "test_user_cleanup",
			"target_username":     req.Username,
			"tables_cleaned":      len(tablesCleared),
			"total_rows_affected": totalRows,
		},
	)

	response := AdminCleanupResponse{
		Success:       true,
		TablesCleared: tablesCleared,
		TotalRows:     totalRows,
		Details: map[string]interface{}{
			"cleanup_timestamp": time.Now().UTC(),
			"admin_username":    adminUsername,
		},
	}

	return JSONResponse(c, http.StatusOK, "Test user cleanup completed", response)
}

// ApproveUser approves a user and optionally updates their storage limit
func ApproveUser(c echo.Context) error {
	targetUsername := c.Param("username")
	if targetUsername == "" {
		return JSONError(c, http.StatusBadRequest, "Username parameter is required")
	}

	// Parse request
	var req AdminApproveRequest
	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}

	if req.ApprovedBy == "" {
		return JSONError(c, http.StatusBadRequest, "approved_by field is required")
	}

	// Get admin username for audit logging
	adminUsername := auth.GetUsernameFromToken(c)

	// Get the target user
	user, err := models.GetUserByUsername(database.DB, targetUsername)
	if err != nil {
		if err == sql.ErrNoRows {
			return JSONError(c, http.StatusNotFound, fmt.Sprintf("User '%s' not found", targetUsername))
		}
		return JSONError(c, http.StatusInternalServerError, "Failed to retrieve user")
	}

	// Approve the user using the existing method
	if err := user.ApproveUser(database.DB, req.ApprovedBy); err != nil {
		logging.ErrorLogger.Printf("Admin user approval failed: %v", err)
		return JSONError(c, http.StatusInternalServerError, "Failed to approve user")
	}

	// Update storage limit if specified in request
	if req.StorageLimitBytes != nil && *req.StorageLimitBytes > 0 {
		_, err = database.DB.Exec("UPDATE users SET storage_limit_bytes = ? WHERE username = ?",
			*req.StorageLimitBytes, targetUsername)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to update storage limit for %s: %v", targetUsername, err)
			return JSONError(c, http.StatusInternalServerError, "User approved but failed to update storage limit")
		}
	}

	// Reload user from database to get updated approval status
	updatedUser, err := models.GetUserByUsername(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to reload user after approval: %v", err)
		return JSONError(c, http.StatusInternalServerError, "Failed to verify user approval")
	}

	// Log admin action for audit trail
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":       "user_approval",
			"target_username": targetUsername,
			"approved_by":     req.ApprovedBy,
		},
	)

	response := AdminApproveResponse{
		Success:    true,
		Username:   updatedUser.Username,
		IsApproved: updatedUser.IsApproved,
		ApprovedBy: req.ApprovedBy,
		ApprovedAt: updatedUser.ApprovedAt.Time,
	}

	return JSONResponse(c, http.StatusOK, "User approved successfully", response)
}

// AdminGetUserStatus returns comprehensive user status information
func AdminGetUserStatus(c echo.Context) error {
	targetUsername := c.Param("username")
	if targetUsername == "" {
		return JSONError(c, http.StatusBadRequest, "Username parameter is required")
	}

	// Get admin username for audit logging
	adminUsername := auth.GetUsernameFromToken(c)

	// Get the target user
	user, err := models.GetUserByUsername(database.DB, targetUsername)
	if err != nil {
		if err == sql.ErrNoRows {
			// User doesn't exist
			response := AdminUserStatusResponse{
				Exists:   false,
				Username: targetUsername,
			}
			return JSONResponse(c, http.StatusOK, "User not found", response)
		}
		return JSONError(c, http.StatusInternalServerError, "Failed to retrieve user")
	}

	// Build comprehensive status response with proper AdminUserInfo mapping
	adminUserInfo := &AdminUserInfo{
		ID:         user.ID,
		Username:   user.Username,
		IsApproved: user.IsApproved,
		IsAdmin:    user.IsAdmin,
		CreatedAt:  user.CreatedAt,
	}

	response := AdminUserStatusResponse{
		Exists:   true,
		Username: targetUsername,
		User:     adminUserInfo,
	}

	// Get comprehensive TOTP status using diagnostic helper
	present, decryptable, enabled, setupCompleted, err := auth.CanDecryptMFASecret(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get TOTP diagnostic status for %s: %v", targetUsername, err)
		response.Details = map[string]interface{}{
			"totp_status_error": "Failed to retrieve TOTP diagnostic status",
		}
	} else {
		response.MFA = &AdminMFAStatus{
			Present:        present,
			Decryptable:    decryptable,
			Enabled:        enabled,
			SetupCompleted: setupCompleted,
		}
	}

	// Get OPAQUE status using RFC-compliant opaque_user_data table
	hasAccount, err := user.HasOPAQUEAccount(database.DB)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get OPAQUE status for %s: %v", targetUsername, err)
		if response.Details == nil {
			response.Details = make(map[string]interface{})
		}
		response.Details["opaque_status_error"] = "Failed to retrieve OPAQUE status"
	} else {
		response.OPAQUE = &AdminOPAQUEStatus{
			HasAccount:   hasAccount,
			RecordsCount: 0, // No longer tracking file-specific OPAQUE records in RFC-compliant design
		}
	}

	// Get token status
	var activeTokens, revokedTokens int
	err = database.DB.QueryRow(
		"SELECT COUNT(*) FROM refresh_tokens WHERE username = ? AND revoked = 0",
		targetUsername,
	).Scan(&activeTokens)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get active tokens for %s: %v", targetUsername, err)
		activeTokens = 0
	}

	err = database.DB.QueryRow(
		"SELECT COUNT(*) FROM revoked_tokens WHERE username = ?",
		targetUsername,
	).Scan(&revokedTokens)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get revoked tokens for %s: %v", targetUsername, err)
		revokedTokens = 0
	}

	response.Tokens = &AdminTokenStatus{
		ActiveRefreshTokens: activeTokens,
		RevokedTokens:       revokedTokens,
	}

	// Billing snapshot: signed microcent balance, billable bytes against the
	// per-instance free baseline, and the current monthly cost projection.
	// Falls back to safe zeros when the user has no credits row.
	response.Billing = buildAdminBillingStatus(database.DB, targetUsername)

	// Log admin action for audit trail
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":       "user_status_check",
			"target_username": targetUsername,
		},
	)

	return JSONResponse(c, http.StatusOK, "User status retrieved", response)
}

// buildAdminBillingStatus is the per-user billing snapshot used by
// AdminGetUserStatus. It reuses the same projection pipeline as
// /api/credits so admin views and user views never disagree.
func buildAdminBillingStatus(db *sql.DB, username string) *AdminBillingStatus {
	credit, err := models.GetUserCredits(db, username)
	var balance int64
	if err == nil && credit != nil {
		balance = credit.BalanceUSDMicrocents
	}

	currentUsage, _ := buildBillingProjection(db, username, balance)

	billable, _ := currentUsage["billable_bytes"].(int64)
	costStr, _ := currentUsage["current_cost_per_month_usd_approx"].(string)

	status := &AdminBillingStatus{
		BalanceUSDMicrocents:         balance,
		FormattedBalance:             models.FormatCreditsUSD(balance),
		BillableBytes:                billable,
		CurrentCostPerMonthUSDApprox: costStr,
	}

	// last_billed_at is read from storage_usage_accumulator if present.
	var lastBilledStr sql.NullString
	if err := db.QueryRow(
		`SELECT last_billed_at FROM storage_usage_accumulator WHERE username = ?`,
		username,
	).Scan(&lastBilledStr); err == nil && lastBilledStr.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", lastBilledStr.String); err == nil {
			status.LastBilledAt = &t
		} else if t, err := time.Parse(time.RFC3339, lastBilledStr.String); err == nil {
			status.LastBilledAt = &t
		}
	}

	return status
}

// GetPendingUsers returns a list of users pending approval
func GetPendingUsers(c echo.Context) error {
	// Get pending users
	pendingUsers, err := models.GetPendingUsers(database.DB)
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to get pending users")
	}

	return JSONResponse(c, http.StatusOK, "Pending users retrieved", pendingUsers)
}

// DeleteUser deletes a user and all associated data
func DeleteUser(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)

	targetUsername := c.Param("username")
	if targetUsername == "" {
		return JSONError(c, http.StatusBadRequest, "Username parameter required")
	}

	// Prevent self-deletion
	if adminUsername == targetUsername {
		return JSONError(c, http.StatusBadRequest, "Cannot delete your own account")
	}

	// Get storage provider from context or use global provider
	var storageProvider storage.ObjectStorageProvider

	// Try to get storage provider from context first
	if sp := c.Get("storage"); sp != nil {
		storageProvider = sp.(storage.ObjectStorageProvider)
	} else {
		storageProvider = storage.Registry.Primary()
	}

	// Start transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()

	// Get user's files for cleanup
	rows, err := tx.Query("SELECT file_id, storage_id FROM file_metadata WHERE owner_username = ?", targetUsername)
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to retrieve user's files")
	}

	var fileIDs []string
	var storageIDs []string
	for rows.Next() {
		var fileID, storageID string
		if err := rows.Scan(&fileID, &storageID); err != nil {
			rows.Close()
			return JSONError(c, http.StatusInternalServerError, "Failed to scan file IDs")
		}
		fileIDs = append(fileIDs, fileID)
		storageIDs = append(storageIDs, storageID)
	}
	rows.Close()

	// Remove files from storage first
	for i, storageID := range storageIDs {
		if storageProvider != nil {
			// Use proper RemoveObjectOptions type
			if err := storageProvider.RemoveObject(c.Request().Context(), storageID, storage.RemoveObjectOptions{}); err != nil {
				return JSONError(c, http.StatusInternalServerError, fmt.Sprintf("Failed to delete user's file from storage: %s", storageID))
			}
		}

		// Remove file metadata after successful storage deletion
		if _, err := tx.Exec("DELETE FROM file_metadata WHERE file_id = ?", fileIDs[i]); err != nil {
			return JSONError(c, http.StatusInternalServerError, fmt.Sprintf("Failed to delete file metadata for: %s", storageIDs[i]))
		}
	}

	// Delete user's file shares from the current shares table
	if _, err := tx.Exec("DELETE FROM file_share_keys WHERE owner_username = ?", targetUsername); err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to delete user's file shares")
	}

	// Soft-delete user record. Set deleted_at timestamp instead of hard-deleting the row.
	// This preserves audit records and structural integrity while immediately locking out the user.
	if _, err := tx.Exec("UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE username = ?", targetUsername); err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to soft-delete user record")
	}

	// Log admin action
	if err := LogAdminAction(tx, adminUsername, "delete_user", targetUsername, ""); err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to log admin action")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to commit transaction")
	}

	return JSONResponse(c, http.StatusOK, "User deleted successfully", nil)
}

// UpdateUser updates user properties
func UpdateUser(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)

	targetUsername := c.Param("username")
	if targetUsername == "" {
		return JSONError(c, http.StatusBadRequest, "Username parameter required")
	}

	// Parse request body
	var req struct {
		IsApproved        *bool  `json:"is_approved"`
		IsAdmin           *bool  `json:"is_admin"`
		StorageLimitBytes *int64 `json:"storage_limit_bytes"`
	}

	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request")
	}

	// Check if any fields to update
	if req.IsApproved == nil && req.IsAdmin == nil && req.StorageLimitBytes == nil {
		return JSONError(c, http.StatusBadRequest, "No updatable fields provided")
	}

	// Start transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()

	// Verify target user exists
	var exists int
	err = tx.QueryRow("SELECT 1 FROM users WHERE username = ?", targetUsername).Scan(&exists)
	if err == sql.ErrNoRows {
		return JSONError(c, http.StatusNotFound, "Target user not found")
	} else if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to check target user")
	}

	// Build update query and collect details
	var setParts []string
	var args []interface{}
	var details []string

	if req.IsApproved != nil {
		// Prevent admin from revoking own approval
		if targetUsername == adminUsername && !*req.IsApproved {
			return JSONError(c, http.StatusBadRequest, "Admins cannot revoke their own approval status.")
		}
		if !*req.IsApproved {
			return JSONError(c, http.StatusBadRequest,
				"Use POST /api/admin/users/:username/revoke to unapprove a user and terminate sessions")
		}
		setParts = append(setParts, "is_approved = ?")
		args = append(args, *req.IsApproved)
		details = append(details, fmt.Sprintf("isApproved: %t", *req.IsApproved))
	}

	if req.IsAdmin != nil {
		setParts = append(setParts, "is_admin = ?")
		args = append(args, *req.IsAdmin)
		details = append(details, fmt.Sprintf("isAdmin: %t", *req.IsAdmin))
	}

	if req.StorageLimitBytes != nil {
		setParts = append(setParts, "storage_limit_bytes = ?")
		args = append(args, *req.StorageLimitBytes)
		details = append(details, fmt.Sprintf("storageLimitBytes: %d", *req.StorageLimitBytes))
	}

	// Execute update
	query := fmt.Sprintf("UPDATE users SET %s WHERE username = ?", strings.Join(setParts, ", "))
	args = append(args, targetUsername)

	if _, err := tx.Exec(query, args...); err != nil {
		if req.IsApproved != nil && !*req.IsApproved {
			return JSONError(c, http.StatusInternalServerError, "Failed to update approval status")
		}
		return JSONError(c, http.StatusInternalServerError, "Failed to update user")
	}

	// Log admin action
	detailsStr := "Updated fields: " + strings.Join(details, ", ")
	if err := LogAdminAction(tx, adminUsername, "update_user", targetUsername, detailsStr); err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to log admin action")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to commit transaction")
	}

	return JSONResponse(c, http.StatusOK, "User updated successfully", nil)
}

// ListUsers returns a list of all users
func ListUsers(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)

	// Get all users with TOTP status and file count
	rows, err := database.DB.Query(`
		SELECT u.username, u.is_approved, u.is_admin, u.storage_limit_bytes, u.total_storage_bytes,
		       u.registration_date, u.last_login,
		       CASE WHEN mc.setup_completed = 1 THEN 1 ELSE 0 END AS mfa_enabled,
		       COALESCE(fm.file_count, 0) AS file_count
		FROM users u
		LEFT JOIN user_mfa_credentials mc ON u.username = mc.username
		LEFT JOIN (SELECT owner_username, COUNT(*) AS file_count FROM file_metadata GROUP BY owner_username) fm ON u.username = fm.owner_username
		WHERE u.deleted_at IS NULL
		ORDER BY u.registration_date DESC`)

	if err == sql.ErrNoRows {
		return JSONResponse(c, http.StatusOK, "Users retrieved", map[string]interface{}{
			"users": []interface{}{},
		})
	} else if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to retrieve users")
	}
	defer rows.Close()

	users := make([]map[string]interface{}, 0)
	for rows.Next() {
		var username sql.NullString
		var isApprovedRaw, isAdminRaw, mfaEnabledRaw, fileCountRaw interface{}
		var storageLimitBytes, totalStorageBytes sql.NullFloat64
		var registrationDate sql.NullString
		var lastLogin sql.NullString

		err := rows.Scan(&username, &isApprovedRaw, &isAdminRaw, &storageLimitBytes, &totalStorageBytes,
			&registrationDate, &lastLogin, &mfaEnabledRaw, &fileCountRaw)
		if err != nil {
			logging.ErrorLogger.Printf("ListUsers scan error: %v", err)
			return JSONError(c, http.StatusInternalServerError, "Error processing user data")
		}

		// Convert boolean values from rqlite driver (may come as bool, int64, or string)
		isApproved := models.ScanBool(isApprovedRaw)
		isAdmin := models.ScanBool(isAdminRaw)
		mfaEnabled := models.ScanBool(mfaEnabledRaw)

		// Extract values with safe defaults for NULL columns
		storageLimit := int64(0)
		if storageLimitBytes.Valid {
			storageLimit = int64(storageLimitBytes.Float64)
		}
		totalStorage := int64(0)
		if totalStorageBytes.Valid {
			totalStorage = int64(totalStorageBytes.Float64)
		}

		// Calculate storage usage percentage
		var usagePercent float64
		if storageLimit > 0 {
			usagePercent = (float64(totalStorage) / float64(storageLimit)) * 100
		}

		// Format total storage for display
		totalStorageReadable := formatBytes(totalStorage)

		// Format registration date (rqlite returns timestamps as strings)
		var registrationDateFormatted string
		if registrationDate.Valid && registrationDate.String != "" {
			// Try to parse and reformat, otherwise use raw string
			if t, err := time.Parse("2006-01-02 15:04:05", registrationDate.String); err == nil {
				registrationDateFormatted = t.Format("2006-01-02")
			} else if t, err := time.Parse(time.RFC3339, registrationDate.String); err == nil {
				registrationDateFormatted = t.Format("2006-01-02")
			} else {
				registrationDateFormatted = registrationDate.String
			}
		}

		// Format last login (rqlite returns timestamps as strings)
		var lastLoginFormatted string
		if lastLogin.Valid && lastLogin.String != "" {
			if t, err := time.Parse("2006-01-02 15:04:05", lastLogin.String); err == nil {
				lastLoginFormatted = t.Format("2006-01-02 15:04:05")
			} else if t, err := time.Parse(time.RFC3339, lastLogin.String); err == nil {
				lastLoginFormatted = t.Format("2006-01-02 15:04:05")
			} else {
				lastLoginFormatted = lastLogin.String
			}
		}

		fileCount := toInt64(fileCountRaw)

		user := map[string]interface{}{
			"username":               username.String,
			"is_approved":            isApproved,
			"is_admin":               isAdmin,
			"mfa_enabled":            mfaEnabled,
			"file_count":             fileCount,
			"storage_limit_bytes":    storageLimit,
			"total_storage_bytes":    totalStorage,
			"total_storage_readable": totalStorageReadable,
			"usage_percent":          usagePercent,
			"registration_date":      registrationDateFormatted,
			"last_login":             lastLoginFormatted,
		}

		users = append(users, user)
	}

	// Log admin action
	LogAdminAction(database.DB, adminUsername, "list_users", "", "")

	return JSONResponse(c, http.StatusOK, "Users retrieved", map[string]interface{}{
		"users": users,
	})
}

// UpdateUserStorageLimit updates a user's storage limit
func UpdateUserStorageLimit(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)

	targetUsername := c.Param("username")
	if targetUsername == "" {
		return JSONError(c, http.StatusBadRequest, "Username parameter required")
	}

	// Parse request body
	var req struct {
		StorageLimitBytes int64 `json:"storage_limit_bytes"`
	}

	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request")
	}

	if req.StorageLimitBytes <= 0 {
		return JSONError(c, http.StatusBadRequest, "Storage limit must be positive")
	}

	// Update storage limit
	_, err := database.DB.Exec("UPDATE users SET storage_limit_bytes = ? WHERE username = ?",
		req.StorageLimitBytes, targetUsername)
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to update storage limit")
	}

	// Log admin action
	details := fmt.Sprintf("New limit: %d bytes", req.StorageLimitBytes)
	LogAdminAction(database.DB, adminUsername, "update_storage_limit", targetUsername, details)

	return JSONResponse(c, http.StatusOK, "Storage limit updated successfully", nil)
}

// AdminRevokeUser revokes a user's access by setting is_approved to false
func AdminRevokeUser(c echo.Context) error {
	targetUsername := c.Param("username")
	if targetUsername == "" {
		return JSONError(c, http.StatusBadRequest, "Username parameter is required")
	}

	// Get admin username for audit logging
	adminUsername := auth.GetUsernameFromToken(c)

	// Prevent admin from revoking themselves
	if targetUsername == adminUsername {
		return JSONError(c, http.StatusBadRequest, "Cannot revoke your own access")
	}

	// Verify target user exists
	user, err := models.GetUserByUsername(database.DB, targetUsername)
	if err != nil {
		if err == sql.ErrNoRows {
			return JSONError(c, http.StatusNotFound, fmt.Sprintf("User '%s' not found", targetUsername))
		}
		return JSONError(c, http.StatusInternalServerError, "Failed to retrieve user")
	}

	// Check if already revoked
	if !user.IsApproved {
		if err := terminateUserSessions(targetUsername, "admin revoke (already unapproved)"); err != nil {
			logging.ErrorLogger.Printf("Failed to terminate sessions for already-revoked user %s: %v", targetUsername, err)
			return JSONError(c, http.StatusInternalServerError, "Failed to terminate user sessions")
		}
		return JSONResponse(c, http.StatusOK, "User is already revoked; sessions terminated", map[string]interface{}{
			"username":    targetUsername,
			"is_approved": false,
		})
	}

	if err := revokeUserAccess(database.DB, targetUsername, adminUsername, "admin user revoke"); err != nil {
		if err == sql.ErrNoRows {
			return JSONError(c, http.StatusNotFound, fmt.Sprintf("User '%s' not found", targetUsername))
		}
		logging.ErrorLogger.Printf("Failed to revoke user %s: %v", targetUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to revoke user")
	}

	return JSONResponse(c, http.StatusOK, "User access revoked successfully", map[string]interface{}{
		"username":    targetUsername,
		"is_approved": false,
		"revoked_by":  adminUsername,
	})
}

// AdminSystemStatus returns system status overview including uptime, version, storage and user statistics
func AdminSystemStatus(c echo.Context) error {
	// Get admin username for audit logging
	adminUsername := auth.GetUsernameFromToken(c)

	// Gather user statistics
	var totalUsers, activeUsers, adminUsers, pendingUsers int
	err := database.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&totalUsers)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to count total users: %v", err)
	}
	err = database.DB.QueryRow("SELECT COUNT(*) FROM users WHERE is_approved = 1 AND deleted_at IS NULL").Scan(&activeUsers)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to count active users: %v", err)
	}
	err = database.DB.QueryRow("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND deleted_at IS NULL").Scan(&adminUsers)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to count admin users: %v", err)
	}
	err = database.DB.QueryRow("SELECT COUNT(*) FROM users WHERE is_approved = 0 AND deleted_at IS NULL").Scan(&pendingUsers)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to count pending users: %v", err)
	}

	// Gather storage statistics
	// Scan as interface{} because rqlite returns large aggregates as float64 in scientific notation.
	var totalFilesRaw, totalSizeBytesRaw, avgFileSizeBytesRaw interface{}
	err = database.DB.QueryRow("SELECT COUNT(*), COALESCE(SUM(size_bytes), 0), COALESCE(AVG(size_bytes), 0) FROM file_metadata").Scan(&totalFilesRaw, &totalSizeBytesRaw, &avgFileSizeBytesRaw)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get storage stats: %v", err)
	}
	totalFiles := toInt64(totalFilesRaw)
	totalSizeBytes := toInt64(totalSizeBytesRaw)
	avgFileSizeBytes := toInt64(avgFileSizeBytesRaw)

	// Gather TOTP statistics
	var mfaEnabledUsers int
	err = database.DB.QueryRow("SELECT COUNT(*) FROM user_mfa_credentials WHERE setup_completed = 1").Scan(&mfaEnabledUsers)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to count TOTP users: %v", err)
	}

	response := map[string]interface{}{
		"version":    "1.0.0",
		"go_version": runtime.Version(),
		"users": map[string]interface{}{
			"total_users":      totalUsers,
			"active_users":     activeUsers,
			"admin_users":      adminUsers,
			"pending_approval": pendingUsers,
		},
		"storage": map[string]interface{}{
			"total_files":             totalFiles,
			"total_size_bytes":        totalSizeBytes,
			"average_file_size_bytes": avgFileSizeBytes,
		},
		"security": map[string]interface{}{
			"mfa_enabled_users": mfaEnabledUsers,
		},
	}

	// Log admin action for audit trail
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation": "system_status",
		},
	)

	return JSONResponse(c, http.StatusOK, "System status retrieved", response)
}

// AdminSystemHealth returns aggregated component health for the admin API.
func AdminSystemHealth(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)

	if monitoring.DefaultHealthMonitor == nil {
		return JSONError(c, http.StatusInternalServerError, "Health monitor not initialized")
	}

	status := monitoring.DefaultHealthMonitor.GetHealthStatus()

	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":      "system_health_check",
			"overall_status": string(status.Status),
		},
	)

	return JSONResponse(c, http.StatusOK, "System health status retrieved", status)
}

// AdminSecurityEvents exposes existing security event logs via admin API.
// Supports query parameters for filtering:
//   - type: filter by event type (e.g. "share_not_found", "opaque_login_failure")
//   - severity: filter by severity ("INFO", "WARNING", "CRITICAL")
//   - entity_id: filter by entity ID (HMAC-based, 16-char hex)
//   - limit: max events to return (default 100, max 500)
func AdminSecurityEvents(c echo.Context) error {
	// Get admin username for audit logging
	adminUsername := auth.GetUsernameFromToken(c)

	// Use the default security event logger to get recent events
	if logging.DefaultSecurityEventLogger == nil {
		return JSONError(c, http.StatusInternalServerError, "Security event logger not initialized")
	}

	// Parse query parameter filters
	limit := 100
	if limitStr := c.QueryParam("limit"); limitStr != "" {
		if parsedLimit, err := fmt.Sscanf(limitStr, "%d", &limit); err != nil || parsedLimit != 1 {
			limit = 100
		}
		if limit < 1 {
			limit = 1
		}
		if limit > 500 {
			limit = 500
		}
	}

	filters := logging.SecurityEventFilters{
		Limit: limit,
	}

	if eventType := c.QueryParam("type"); eventType != "" {
		filters.EventType = logging.SecurityEventType(eventType)
	}

	if severity := c.QueryParam("severity"); severity != "" {
		filters.Severity = logging.SecurityEventSeverity(strings.ToUpper(severity))
	}

	if entityID := c.QueryParam("entity_id"); entityID != "" {
		filters.EntityID = entityID
	}

	events, err := logging.DefaultSecurityEventLogger.GetSecurityEvents(filters)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to retrieve security events: %v", err)
		return JSONError(c, http.StatusInternalServerError, "Failed to retrieve security events")
	}

	// Log admin action for audit trail
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":    "security_events_access",
			"events_count": len(events),
		},
	)

	response := map[string]interface{}{
		"events": events,
		"count":  len(events),
		"limit":  limit,
	}

	return JSONResponse(c, http.StatusOK, "Security events retrieved", response)
}

// toInt64 converts an interface{} value to int64, handling the various types
// that rqlite driver may return for numeric columns (int64, float64).
// Returns 0 for nil or unrecognized types.
func toInt64(v interface{}) int64 {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case int64:
		return val
	case float64:
		return int64(val)
	case int:
		return int64(val)
	default:
		return 0
	}
}

// AdminListUserFiles lists all files owned by a specific user
func AdminListUserFiles(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)
	targetUsername := c.Param("username")

	if targetUsername == "" {
		return JSONError(c, http.StatusBadRequest, "Username parameter required")
	}

	// Verify target user exists
	_, err := models.GetUserByUsername(database.DB, targetUsername)
	if err != nil {
		return JSONError(c, http.StatusNotFound, "User not found")
	}

	// LEFT JOIN with file_storage_locations to include provider IDs per file.
	// GROUP_CONCAT aggregates all active provider IDs into a comma-separated string.
	rows, err := database.DB.Query(`
		SELECT fm.file_id, fm.storage_id, fm.size_bytes, fm.chunk_count, fm.upload_date,
		       fm.password_type,
		       COALESCE(GROUP_CONCAT(fsl.provider_id), '') AS locations
		FROM file_metadata fm
		LEFT JOIN file_storage_locations fsl
			ON fm.file_id = fsl.file_id AND fsl.status = 'active'
		WHERE fm.owner_username = ?
		GROUP BY fm.file_id
		ORDER BY fm.upload_date DESC`, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to list files for %s: %v", adminUsername, targetUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to list user files")
	}
	defer rows.Close()

	var files []map[string]interface{}
	for rows.Next() {
		var fileID, storageID, uploadDate, passwordType, locationsStr string
		var sizeBytesRaw, chunkCountRaw interface{}
		if err := rows.Scan(&fileID, &storageID, &sizeBytesRaw, &chunkCountRaw, &uploadDate, &passwordType, &locationsStr); err != nil {
			logging.ErrorLogger.Printf("Admin %s: scan error listing files for %s: %v", adminUsername, targetUsername, err)
			continue
		}

		// Parse comma-separated provider IDs into a string slice
		var locations []string
		if locationsStr != "" {
			locations = strings.Split(locationsStr, ",")
		}

		files = append(files, map[string]interface{}{
			"file_id":       fileID,
			"storage_id":    storageID,
			"size_bytes":    toInt64(sizeBytesRaw),
			"chunk_count":   toInt64(chunkCountRaw),
			"upload_date":   uploadDate,
			"password_type": passwordType,
			"locations":     locations,
		})
	}

	logging.InfoLogger.Printf("ADMIN: %s listed files for user %s (%d files)", adminUsername, targetUsername, len(files))

	return JSONResponse(c, http.StatusOK, "User files retrieved", map[string]interface{}{
		"username": targetUsername,
		"files":    files,
		"count":    len(files),
	})
}

// AdminListUserShares lists all shares owned by a specific user
func AdminListUserShares(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)
	targetUsername := c.Param("username")

	if targetUsername == "" {
		return JSONError(c, http.StatusBadRequest, "Username parameter required")
	}

	// Verify target user exists
	_, err := models.GetUserByUsername(database.DB, targetUsername)
	if err != nil {
		return JSONError(c, http.StatusNotFound, "User not found")
	}

	rows, err := database.DB.Query(`
		SELECT share_id, file_id, created_at, expires_at, access_count, max_accesses, revoked_at
		FROM file_share_keys
		WHERE owner_username = ?
		ORDER BY created_at DESC`, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to list shares for %s: %v", adminUsername, targetUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to list user shares")
	}
	defer rows.Close()

	var shares []map[string]interface{}
	for rows.Next() {
		var shareID, fileID, createdAt string
		var expiresAt, revokedAt sql.NullString
		var accessCountRaw, maxAccessesRaw interface{}
		if err := rows.Scan(&shareID, &fileID, &createdAt, &expiresAt, &accessCountRaw, &maxAccessesRaw, &revokedAt); err != nil {
			logging.ErrorLogger.Printf("Admin %s: scan error listing shares for %s: %v", adminUsername, targetUsername, err)
			continue
		}
		share := map[string]interface{}{
			"share_id":     shareID,
			"file_id":      fileID,
			"created_at":   createdAt,
			"access_count": toInt64(accessCountRaw),
			"is_revoked":   revokedAt.Valid,
		}
		if expiresAt.Valid {
			share["expires_at"] = expiresAt.String
		}
		if maxAccessesRaw != nil {
			share["max_accesses"] = toInt64(maxAccessesRaw)
		}
		if revokedAt.Valid {
			share["revoked_at"] = revokedAt.String
		}
		shares = append(shares, share)
	}

	logging.InfoLogger.Printf("ADMIN: %s listed shares for user %s (%d shares)", adminUsername, targetUsername, len(shares))

	return JSONResponse(c, http.StatusOK, "User shares retrieved", map[string]interface{}{
		"username": targetUsername,
		"shares":   shares,
		"count":    len(shares),
	})
}

// AdminDeleteFile deletes a specific file by file_id (from storage + DB)
func AdminDeleteFile(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)
	fileID := c.Param("fileId")

	if fileID == "" {
		return JSONError(c, http.StatusBadRequest, "File ID parameter required")
	}

	// Get storage provider
	var storageProvider storage.ObjectStorageProvider
	if sp := c.Get("storage"); sp != nil {
		storageProvider = sp.(storage.ObjectStorageProvider)
	} else {
		storageProvider = storage.Registry.Primary()
	}

	// Start transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()

	// Get file metadata
	var storageID, ownerUsername string
	err = tx.QueryRow("SELECT storage_id, owner_username FROM file_metadata WHERE file_id = ?", fileID).Scan(&storageID, &ownerUsername)
	if err == sql.ErrNoRows {
		return JSONError(c, http.StatusNotFound, "File not found")
	} else if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to get file metadata")
	}

	// Delete from storage
	if storageProvider != nil {
		if err := storageProvider.RemoveObject(c.Request().Context(), storageID, storage.RemoveObjectOptions{}); err != nil {
			logging.ErrorLogger.Printf("Admin %s failed to delete file %s from storage: %v", adminUsername, fileID, err)
			return JSONError(c, http.StatusInternalServerError, "Failed to delete file from storage")
		}
	}

	// Delete associated shares
	if _, err := tx.Exec("DELETE FROM file_share_keys WHERE file_id = ?", fileID); err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to delete file shares")
	}

	// Delete file metadata
	if _, err := tx.Exec("DELETE FROM file_metadata WHERE file_id = ?", fileID); err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to delete file metadata")
	}

	// Log admin action
	if err := LogAdminAction(tx, adminUsername, "delete_file", ownerUsername, fmt.Sprintf("file_id: %s", fileID)); err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to log admin action")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to commit transaction")
	}

	logging.InfoLogger.Printf("ADMIN: %s deleted file %s (owner: %s)", adminUsername, fileID, ownerUsername)

	return JSONResponse(c, http.StatusOK, "File deleted successfully", map[string]interface{}{
		"file_id": fileID,
		"owner":   ownerUsername,
	})
}

// AdminRevokeShare revokes a specific share by share_id
func AdminRevokeShare(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)
	shareID := c.Param("shareId")

	if shareID == "" {
		return JSONError(c, http.StatusBadRequest, "Share ID parameter required")
	}

	// Verify share exists and get owner
	var ownerUsername string
	var revokedAt sql.NullString
	err := database.DB.QueryRow(
		"SELECT owner_username, revoked_at FROM file_share_keys WHERE share_id = ?",
		shareID).Scan(&ownerUsername, &revokedAt)
	if err == sql.ErrNoRows {
		return JSONError(c, http.StatusNotFound, "Share not found")
	} else if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to get share info")
	}

	if revokedAt.Valid {
		return JSONError(c, http.StatusConflict, "Share is already revoked")
	}

	// Revoke the share
	_, err = database.DB.Exec(
		"UPDATE file_share_keys SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = ? WHERE share_id = ?",
		"admin_revocation", shareID)
	if err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to revoke share %s: %v", adminUsername, shareID, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to revoke share")
	}

	// Log admin action
	database.LogUserAction(adminUsername, "admin revoked share", fmt.Sprintf("share_id: %s, owner: %s", shareID, ownerUsername))
	logging.InfoLogger.Printf("ADMIN: %s revoked share %s (owner: %s)", adminUsername, shareID, ownerUsername)

	return JSONResponse(c, http.StatusOK, "Share revoked successfully", map[string]interface{}{
		"share_id": shareID,
		"owner":    ownerUsername,
	})
}

// LogAdminAction logs an admin action to the admin_logs table
func LogAdminAction(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
}, adminUsername, action, targetUsername, details string) error {
	_, err := db.Exec(`
		INSERT INTO admin_logs (admin_username, action, target_username, details) 
		VALUES (?, ?, ?, ?)`,
		adminUsername, action, targetUsername, details)
	return err
}
