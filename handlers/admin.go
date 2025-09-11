package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/monitoring"
	"github.com/84adam/Arkfile/storage"
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
	ApprovedBy string `json:"approved_by" validate:"required"`
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
	TOTP     *AdminTOTPStatus       `json:"totp,omitempty"`
	OPAQUE   *AdminOPAQUEStatus     `json:"opaque,omitempty"`
	Tokens   *AdminTokenStatus      `json:"tokens,omitempty"`
	Details  map[string]interface{} `json:"details,omitempty"`
}

// AdminUserInfo represents basic user information
type AdminUserInfo struct {
	ID         int64     `json:"id"`
	Username   string    `json:"username"`
	Email      *string   `json:"email,omitempty"`
	IsApproved bool      `json:"is_approved"`
	IsAdmin    bool      `json:"is_admin"`
	CreatedAt  time.Time `json:"created_at"`
}

// AdminTOTPStatus represents TOTP status information
type AdminTOTPStatus struct {
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

// AdminCleanupTestUser performs comprehensive cleanup of test user data
func AdminCleanupTestUser(c echo.Context) error {
	// Parse request
	var req AdminCleanupRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	// Validate request
	if req.Username == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username is required")
	}

	if !req.Confirm {
		return echo.NewHTTPError(http.StatusBadRequest, "Confirmation is required for cleanup operation")
	}

	// Get admin username for audit logging
	adminUsername := auth.GetUsernameFromToken(c)

	// Perform cleanup in a transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start cleanup transaction")
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
		{"opaque_password_records", "DELETE FROM opaque_password_records WHERE record_identifier = ? OR associated_username = ?"},
		{"user_totp", "DELETE FROM user_totp WHERE username = ?"},
		{"refresh_tokens", "DELETE FROM refresh_tokens WHERE username = ?"},
		{"totp_usage_log", "DELETE FROM totp_usage_log WHERE username = ?"},
		{"totp_backup_usage", "DELETE FROM totp_backup_usage WHERE username = ?"},
		{"revoked_tokens", "DELETE FROM revoked_tokens WHERE username = ?"},
		{"user_activity", "DELETE FROM user_activity WHERE username = ?"},
	}

	for _, op := range cleanupOperations {
		var result sql.Result
		var err error

		// Handle tables that need different parameter patterns
		if op.table == "opaque_password_records" {
			result, err = tx.Exec(op.query, req.Username, req.Username)
		} else {
			result, err = tx.Exec(op.query, req.Username)
		}

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
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to complete cleanup operation")
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

	return c.JSON(http.StatusOK, response)
}

// AdminTOTPDecryptCheck provides TOTP diagnostic information for development
func AdminTOTPDecryptCheck(c echo.Context) error {
	// Only available in debug mode
	debugMode := strings.ToLower(os.Getenv("DEBUG_MODE"))
	if debugMode != "true" && debugMode != "1" {
		return echo.NewHTTPError(http.StatusNotFound, "Endpoint not available")
	}

	targetUsername := c.Param("username")
	if targetUsername == "" {
		// Use current user if no username specified
		targetUsername = auth.GetUsernameFromToken(c)
		if targetUsername == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "Username required")
		}
	}

	// Get admin username for audit logging
	adminUsername := auth.GetUsernameFromToken(c)

	// Use the diagnostic helper we added to auth/totp.go
	present, decryptable, enabled, setupCompleted, err := auth.CanDecryptTOTPSecret(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("TOTP decrypt check failed for %s: %v", targetUsername, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check TOTP decrypt status")
	}

	// Get additional metadata for debugging
	var createdAt, lastUsed interface{}
	err = database.DB.QueryRow(`
		SELECT created_at, last_used 
		FROM user_totp 
		WHERE username = ?`,
		targetUsername,
	).Scan(&createdAt, &lastUsed)

	response := map[string]interface{}{
		"username":        targetUsername,
		"present":         present,
		"decryptable":     decryptable,
		"enabled":         enabled,
		"setup_completed": setupCompleted,
		"created_at":      createdAt,
		"last_used":       lastUsed,
		"debug_info": map[string]interface{}{
			"checked_by":    adminUsername,
			"checked_at":    time.Now().UTC(),
			"debug_enabled": true,
		},
	}

	// Log admin action for audit trail
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":       "totp_decrypt_check",
			"target_username": targetUsername,
			"present":         present,
			"decryptable":     decryptable,
		},
	)

	return c.JSON(http.StatusOK, response)
}

// AdminApproveUser approves a specific user for testing
func AdminApproveUser(c echo.Context) error {
	targetUsername := c.Param("username")
	if targetUsername == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username parameter is required")
	}

	// Parse request
	var req AdminApproveRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	if req.ApprovedBy == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "approved_by field is required")
	}

	// Get admin username for audit logging
	adminUsername := auth.GetUsernameFromToken(c)

	// Get the target user
	user, err := models.GetUserByUsername(database.DB, targetUsername)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, fmt.Sprintf("User '%s' not found", targetUsername))
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve user")
	}

	// Approve the user using the existing method
	if err := user.ApproveUser(database.DB, req.ApprovedBy); err != nil {
		logging.ErrorLogger.Printf("Admin user approval failed: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to approve user")
	}

	// Reload user from database to get updated approval status
	updatedUser, err := models.GetUserByUsername(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to reload user after approval: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify user approval")
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

	return c.JSON(http.StatusOK, response)
}

// AdminGetUserStatus returns comprehensive user status information
func AdminGetUserStatus(c echo.Context) error {
	targetUsername := c.Param("username")
	if targetUsername == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username parameter is required")
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
			return c.JSON(http.StatusOK, response)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve user")
	}

	// Build comprehensive status response with proper AdminUserInfo mapping
	adminUserInfo := &AdminUserInfo{
		ID:         user.ID,
		Username:   user.Username,
		Email:      user.Email,
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
	present, decryptable, enabled, setupCompleted, err := auth.CanDecryptTOTPSecret(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get TOTP diagnostic status for %s: %v", targetUsername, err)
		response.Details = map[string]interface{}{
			"totp_status_error": "Failed to retrieve TOTP diagnostic status",
		}
	} else {
		response.TOTP = &AdminTOTPStatus{
			Present:        present,
			Decryptable:    decryptable,
			Enabled:        enabled,
			SetupCompleted: setupCompleted,
		}
	}

	// Get OPAQUE status
	opaqueStatus, err := user.GetOPAQUEAccountStatus(database.DB)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get OPAQUE status for %s: %v", targetUsername, err)
		if response.Details == nil {
			response.Details = make(map[string]interface{})
		}
		response.Details["opaque_status_error"] = "Failed to retrieve OPAQUE status"
	} else {
		response.OPAQUE = &AdminOPAQUEStatus{
			HasAccount:   opaqueStatus.HasAccountPassword,
			RecordsCount: opaqueStatus.FilePasswordCount,
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

	return c.JSON(http.StatusOK, response)
}

// GetPendingUsers returns a list of users pending approval
func GetPendingUsers(c echo.Context) error {
	// Get admin user and verify admin privileges
	adminUsername := auth.GetUsernameFromToken(c)
	adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user")
	}

	if !adminUser.IsAdmin {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get pending users
	pendingUsers, err := models.GetPendingUsers(database.DB)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get pending users")
	}

	return c.JSON(http.StatusOK, pendingUsers)
}

// DeleteUser deletes a user and all associated data
func DeleteUser(c echo.Context) error {
	// Get admin user and verify admin privileges first
	adminUsername := auth.GetUsernameFromToken(c)
	adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get admin user")
	}

	if !adminUser.IsAdmin {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	targetUsername := c.Param("username")
	if targetUsername == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username parameter required")
	}

	// Prevent self-deletion
	if adminUsername == targetUsername {
		return echo.NewHTTPError(http.StatusBadRequest, "Cannot delete your own account")
	}

	// Get storage provider from context or use global provider
	var storageProvider storage.ObjectStorageProvider

	// Try to get storage provider from context first
	if sp := c.Get("storage"); sp != nil {
		storageProvider = sp.(storage.ObjectStorageProvider)
	} else {
		// Fallback to global storage provider (used in tests and production)
		storageProvider = storage.Provider
	}

	// Start transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()

	// Get user's files for cleanup
	rows, err := tx.Query("SELECT file_id, storage_id FROM file_metadata WHERE owner_username = ?", targetUsername)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve user's files")
	}

	var fileIDs []string
	var storageIDs []string
	for rows.Next() {
		var fileID, storageID string
		if err := rows.Scan(&fileID, &storageID); err != nil {
			rows.Close()
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to scan file IDs")
		}
		fileIDs = append(fileIDs, fileID)
		storageIDs = append(storageIDs, storageID)
	}
	rows.Close()

	// Remove files from storage first
	for i, storageID := range storageIDs {
		if storageProvider != nil {
			// Import minio and use proper RemoveObjectOptions type
			if err := storageProvider.RemoveObject(c.Request().Context(), storageID, minio.RemoveObjectOptions{}); err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to delete user's file from storage: %s", storageID))
			}
		}

		// Remove file metadata after successful storage deletion
		if _, err := tx.Exec("DELETE FROM file_metadata WHERE file_id = ?", fileIDs[i]); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to delete file metadata for: %s", storageIDs[i]))
		}
	}

	// Delete user's file shares
	if _, err := tx.Exec("DELETE FROM file_shares WHERE owner_username = ?", targetUsername); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete user's file shares")
	}

	// Delete user record
	if _, err := tx.Exec("DELETE FROM users WHERE username = ?", targetUsername); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete user record")
	}

	// Log admin action
	if err := LogAdminAction(tx, adminUsername, "delete_user", targetUsername, ""); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to log admin action")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit transaction")
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "User deleted successfully",
	})
}

// UpdateUser updates user properties
func UpdateUser(c echo.Context) error {
	// Get admin user and verify admin privileges first
	adminUsername := auth.GetUsernameFromToken(c)
	adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get admin user")
	}

	if !adminUser.IsAdmin {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	targetUsername := c.Param("username")
	if targetUsername == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username parameter required")
	}

	// Parse request body
	var req struct {
		IsApproved        *bool  `json:"is_approved"`
		IsAdmin           *bool  `json:"is_admin"`
		StorageLimitBytes *int64 `json:"storage_limit_bytes"`
	}

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	// Check if any fields to update
	if req.IsApproved == nil && req.IsAdmin == nil && req.StorageLimitBytes == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "No updatable fields provided")
	}

	// Start transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()

	// Verify target user exists
	var exists int
	err = tx.QueryRow("SELECT 1 FROM users WHERE username = ?", targetUsername).Scan(&exists)
	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Target user not found")
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check target user")
	}

	// Build update query and collect details
	var setParts []string
	var args []interface{}
	var details []string

	if req.IsApproved != nil {
		// Prevent admin from revoking own approval
		if targetUsername == adminUsername && !*req.IsApproved {
			return echo.NewHTTPError(http.StatusBadRequest, "Admins cannot revoke their own approval status.")
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
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update approval status")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update user")
	}

	// Log admin action
	detailsStr := "Updated fields: " + strings.Join(details, ", ")
	if err := LogAdminAction(tx, adminUsername, "update_user", targetUsername, detailsStr); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to log admin action")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit transaction")
	}

	// If revoking approval, tokens would be invalidated in a real implementation
	// For now, just log the action
	if req.IsApproved != nil && !*req.IsApproved {
		logging.InfoLogger.Printf("User %s approval revoked by admin %s", targetUsername, adminUsername)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "User updated successfully",
	})
}

// ListUsers returns a list of all users
func ListUsers(c echo.Context) error {
	// Get admin user and verify admin privileges
	adminUsername := auth.GetUsernameFromToken(c)
	adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get admin user")
	}

	if !adminUser.IsAdmin {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get all users except the current admin
	rows, err := database.DB.Query(`
		SELECT username, email, is_approved, is_admin, storage_limit_bytes, total_storage_bytes,
		       registration_date, last_login
		FROM users
		ORDER BY registration_date DESC`)

	if err == sql.ErrNoRows {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"users": []interface{}{},
		})
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve users")
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var username, email sql.NullString
		var isApproved, isAdmin bool
		var storageLimitBytes, totalStorageBytes int64
		var registrationDate time.Time
		var lastLogin sql.NullTime

		err := rows.Scan(&username, &email, &isApproved, &isAdmin, &storageLimitBytes, &totalStorageBytes,
			&registrationDate, &lastLogin)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Error processing user data")
		}

		// Filter out admins from the list (optional, or keep them)
		if username.String == adminUsername {
			continue // Skip the current admin user
		}

		// Calculate storage usage percentage
		var usagePercent float64
		if storageLimitBytes > 0 {
			usagePercent = (float64(totalStorageBytes) / float64(storageLimitBytes)) * 100
		}

		// Format total storage for display
		totalStorageReadable := formatBytes(totalStorageBytes)

		// Format last login
		var lastLoginFormatted string
		if lastLogin.Valid {
			lastLoginFormatted = lastLogin.Time.Format("2006-01-02 15:04:05")
		}

		user := map[string]interface{}{
			"username":               username.String,
			"email":                  email.String,
			"is_approved":            isApproved,
			"is_admin":               isAdmin,
			"storage_limit_bytes":    storageLimitBytes,
			"total_storage_bytes":    totalStorageBytes,
			"total_storage_readable": totalStorageReadable,
			"usage_percent":          usagePercent,
			"registration_date":      registrationDate.Format("2006-01-02"),
			"last_login":             lastLoginFormatted,
		}

		users = append(users, user)
	}

	// Log admin action
	LogAdminAction(database.DB, adminUsername, "list_users", "", "")

	return c.JSON(http.StatusOK, map[string]interface{}{
		"users": users,
	})
}

// ApproveUser approves a user
func ApproveUser(c echo.Context) error {
	// Get admin user and verify admin privileges first
	adminUsername := auth.GetUsernameFromToken(c)
	adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get admin user")
	}

	if !adminUser.IsAdmin {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	targetUsername := c.Param("username")
	if targetUsername == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username parameter required")
	}

	// Get target user
	targetUser, err := models.GetUserByUsername(database.DB, targetUsername)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	// Approve user
	if err := targetUser.ApproveUser(database.DB, adminUsername); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to approve user")
	}

	// Log admin action
	LogAdminAction(database.DB, adminUsername, "approve_user", targetUsername, "")

	return c.JSON(http.StatusOK, map[string]string{
		"message": "User approved successfully",
	})
}

// UpdateUserStorageLimit updates a user's storage limit
func UpdateUserStorageLimit(c echo.Context) error {
	// Get admin user and verify admin privileges first
	adminUsername := auth.GetUsernameFromToken(c)
	adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get admin user")
	}

	if !adminUser.IsAdmin {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	targetUsername := c.Param("username")
	if targetUsername == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username parameter required")
	}

	// Parse request body
	var req struct {
		StorageLimitBytes int64 `json:"storage_limit_bytes"`
	}

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	if req.StorageLimitBytes <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Storage limit must be positive")
	}

	// Update storage limit
	_, err = database.DB.Exec("UPDATE users SET storage_limit_bytes = ? WHERE username = ?",
		req.StorageLimitBytes, targetUsername)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update storage limit")
	}

	// Log admin action
	details := fmt.Sprintf("New limit: %d bytes", req.StorageLimitBytes)
	LogAdminAction(database.DB, adminUsername, "update_storage_limit", targetUsername, details)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Storage limit updated successfully",
	})
}

// AdminSystemHealth bridges existing monitoring infrastructure to admin API endpoints
func AdminSystemHealth(c echo.Context) error {
	// Get admin username for audit logging
	adminUsername := auth.GetUsernameFromToken(c)

	// Create a HealthMonitor instance for this request
	// Note: In a production system, this would ideally be a global instance
	// but for Phase 2 we're implementing the quick bridge approach
	cfg, err := config.LoadConfig()
	if err != nil {
		logging.ErrorLogger.Printf("Failed to load config for health check: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Configuration error")
	}

	healthMonitor := monitoring.NewHealthMonitor(database.DB, cfg, "arkfile-server")
	status := healthMonitor.GetHealthStatus()

	// Log admin action for audit trail
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

	return c.JSON(http.StatusOK, status)
}

// AdminSecurityEvents exposes existing security event logs via admin API
func AdminSecurityEvents(c echo.Context) error {
	// Get admin username for audit logging
	adminUsername := auth.GetUsernameFromToken(c)

	// Use the default security event logger to get recent events
	if logging.DefaultSecurityEventLogger == nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Security event logger not initialized")
	}

	// Create filters for recent events (limit to 100 for performance)
	filters := logging.SecurityEventFilters{
		Limit: 100,
	}

	events, err := logging.DefaultSecurityEventLogger.GetSecurityEvents(filters)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to retrieve security events: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve security events")
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
		"limit":  100,
	}

	return c.JSON(http.StatusOK, response)
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
