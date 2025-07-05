package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7" // Import minio for options

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
	"github.com/84adam/arkfile/storage"
)

func CsvString(slice []string) string {
	return strings.Join(slice, ", ")
}

// GetPendingUsers returns a list of users pending approval
func GetPendingUsers(c echo.Context) error {
	adminEmail := auth.GetEmailFromToken(c)

	// Check admin privileges
	user, err := models.GetUserByEmail(database.DB, adminEmail)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user")
	}

	if !user.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get pending users
	users, err := models.GetPendingUsers(database.DB)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get pending users: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get pending users")
	}

	return c.JSON(http.StatusOK, users)
}

// ApproveUser handles user approval by admin
func ApproveUser(c echo.Context) error {
	adminEmail := auth.GetEmailFromToken(c)

	// Check admin privileges
	admin, err := models.GetUserByEmail(database.DB, adminEmail)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get admin user")
	}

	if !admin.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get target user's email
	targetEmail := c.Param("email")
	if targetEmail == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Email parameter required")
	}

	// Get target user
	user, err := models.GetUserByEmail(database.DB, targetEmail)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	// Approve user
	if err := user.ApproveUser(database.DB, adminEmail); err != nil {
		if strings.Contains(err.Error(), "user already approved") {
			return echo.NewHTTPError(http.StatusBadRequest, "User is already approved")
		}
		logging.ErrorLogger.Printf("Failed to approve user: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to approve user")
	}

	// Log admin action
	database.LogAdminAction(adminEmail, "approve_user", targetEmail, "")
	logging.InfoLogger.Printf("User approved: %s by %s", targetEmail, adminEmail)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "User approved successfully",
	})
}

// UpdateUserStorageLimit handles admin updates to user storage limits
func UpdateUserStorageLimit(c echo.Context) error {
	adminEmail := auth.GetEmailFromToken(c)

	// Check admin privileges
	admin, err := models.GetUserByEmail(database.DB, adminEmail)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get admin user")
	}

	if !admin.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get target user's email
	targetEmail := c.Param("email")
	if targetEmail == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Email parameter required")
	}

	// Parse new limit
	var request struct {
		StorageLimit int64 `json:"storage_limit_bytes"`
	}
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	if request.StorageLimit <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Storage limit must be positive")
	}

	// Update storage limit
	_, err = database.DB.Exec(
		"UPDATE users SET storage_limit_bytes = ? WHERE email = ?",
		request.StorageLimit, targetEmail,
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to update storage limit: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update storage limit")
	}

	// Log admin action
	database.LogAdminAction(adminEmail, "update_storage_limit", targetEmail,
		fmt.Sprintf("New limit: %d bytes", request.StorageLimit))
	logging.InfoLogger.Printf("Storage limit updated for %s by %s: %d bytes",
		targetEmail, adminEmail, request.StorageLimit)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Storage limit updated successfully",
	})
}

// ListUsers returns a list of all users in the system
func ListUsers(c echo.Context) error {
	adminEmail := auth.GetEmailFromToken(c)

	// Check admin privileges
	admin, err := models.GetUserByEmail(database.DB, adminEmail)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get admin user")
	}

	if !admin.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Query all users
	rows, err := database.DB.Query(`
		SELECT email, is_approved, is_admin, storage_limit_bytes, total_storage_bytes, 
		       registration_date, last_login
		FROM users
		ORDER BY registration_date DESC
	`)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusOK, map[string]interface{}{"users": []interface{}{}})
		}
		logging.ErrorLogger.Printf("Failed to query users: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve users")
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var (
			email            string
			isApproved       bool
			isAdmin          bool
			storageLimit     int64
			totalStorage     int64
			registrationDate time.Time
			lastLogin        sql.NullTime
		)

		if err := rows.Scan(&email, &isApproved, &isAdmin, &storageLimit, &totalStorage,
			&registrationDate, &lastLogin); err != nil {
			logging.ErrorLogger.Printf("Error scanning user row: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Error processing user data")
		}

		lastLoginStr := ""
		if lastLogin.Valid {
			lastLoginStr = lastLogin.Time.Format(time.RFC3339)
		}

		usagePercent := 0.0
		if storageLimit > 0 {
			usagePercent = float64(totalStorage) / float64(storageLimit) * 100
		}

		if email != adminEmail {
			users = append(users, map[string]interface{}{
				"email":                email,
				"isApproved":           isApproved,
				"isAdmin":              isAdmin,
				"storageLimit":         storageLimit,
				"storageLimitReadable": formatBytes(storageLimit),
				"totalStorage":         totalStorage,
				"totalStorageReadable": formatBytes(totalStorage),
				"usagePercent":         usagePercent,
				"registrationDate":     registrationDate.Format(time.RFC3339),
				"lastLogin":            lastLoginStr,
			})
		}
	}

	if err = rows.Err(); err != nil {
		logging.ErrorLogger.Printf("Error iterating user rows: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error processing user data")
	}

	database.LogAdminAction(adminEmail, "list_users", "", "")
	return c.JSON(http.StatusOK, map[string]interface{}{
		"users": users,
	})
}

// UpdateUser handles updating user details by admin
func UpdateUser(c echo.Context) error {
	adminEmail := auth.GetEmailFromToken(c)

	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("DEBUG: UpdateUser called by admin: %s", adminEmail)
	}

	// Check admin privileges
	admin, err := models.GetUserByEmail(database.DB, adminEmail)
	if err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("DEBUG: Failed to get admin user %s: %v", adminEmail, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get admin user")
	}

	if !admin.HasAdminPrivileges() {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("DEBUG: User %s does not have admin privileges", adminEmail)
		}
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get target user's email
	targetEmail := c.Param("email")
	if targetEmail == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Email parameter required")
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("DEBUG: Attempting to update user: %s", targetEmail)
	}

	// Parse update data
	var request struct {
		IsApproved        *bool  `json:"isApproved"`
		IsAdmin           *bool  `json:"isAdmin"`
		StorageLimitBytes *int64 `json:"storageLimitBytes"`
	}

	if err := c.Bind(&request); err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("DEBUG: Failed to bind request: %v", err)
		}
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("DEBUG: Request data - IsApproved: %v, IsAdmin: %v, StorageLimit: %v",
			request.IsApproved, request.IsAdmin, request.StorageLimitBytes)
	}

	if request.IsApproved == nil && request.IsAdmin == nil && request.StorageLimitBytes == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "No updatable fields provided")
	}

	// Update user fields
	tx, err := database.DB.Begin()
	if err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("DEBUG: Failed to start transaction: %v", err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()

	// Check user exists - handle rqlite type conversion issues
	var existsInterface interface{}
	err = tx.QueryRow("SELECT 1 FROM users WHERE email = ?", targetEmail).Scan(&existsInterface)
	if err == sql.ErrNoRows {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("DEBUG: Target user not found: %s", targetEmail)
		}
		return echo.NewHTTPError(http.StatusNotFound, "Target user not found")
	} else if err != nil {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("DEBUG: Failed to verify user %s: %v", targetEmail, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify user")
	}

	// Convert the result to bool (rqlite returns 1 as float64)
	var exists bool
	switch v := existsInterface.(type) {
	case bool:
		exists = v
	case int:
		exists = v != 0
	case int64:
		exists = v != 0
	case float64:
		exists = v != 0
	default:
		exists = existsInterface != nil
	}

	if !exists {
		if logging.ErrorLogger != nil {
			logging.ErrorLogger.Printf("DEBUG: Target user not found: %s", targetEmail)
		}
		return echo.NewHTTPError(http.StatusNotFound, "Target user not found")
	}

	if logging.InfoLogger != nil {
		logging.InfoLogger.Printf("DEBUG: Target user %s exists, proceeding with update", targetEmail)
	}

	var logDetails []string

	// Update approval status if provided
	if request.IsApproved != nil {
		if targetEmail == adminEmail && !*request.IsApproved {
			return echo.NewHTTPError(http.StatusBadRequest, "Admins cannot revoke their own approval status.")
		}
		_, err = tx.Exec("UPDATE users SET is_approved = ? WHERE email = ?", *request.IsApproved, targetEmail)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to update approval status: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update approval status")
		}
		logDetails = append(logDetails, fmt.Sprintf("isApproved: %t", *request.IsApproved))
		if !*request.IsApproved {
			// Asynchronously revoke tokens
			go auth.DeleteAllRefreshTokensForUser(database.DB, targetEmail)
		}
	}

	// Update admin status if provided
	if request.IsAdmin != nil {
		if targetEmail == adminEmail && !*request.IsAdmin {
			return echo.NewHTTPError(http.StatusBadRequest, "Admins cannot revoke their own admin status.")
		}
		_, err = tx.Exec("UPDATE users SET is_admin = ? WHERE email = ?", *request.IsAdmin, targetEmail)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to update admin status: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update admin status")
		}
		logDetails = append(logDetails, fmt.Sprintf("isAdmin: %t", *request.IsAdmin))
	}

	// Update storage limit if provided
	if request.StorageLimitBytes != nil {
		if *request.StorageLimitBytes <= 0 {
			return echo.NewHTTPError(http.StatusBadRequest, "Storage limit must be positive")
		}
		_, err = tx.Exec("UPDATE users SET storage_limit_bytes = ? WHERE email = ?", *request.StorageLimitBytes, targetEmail)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to update storage limit: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update storage limit")
		}
		logDetails = append(logDetails, fmt.Sprintf("storageLimitBytes: %d", *request.StorageLimitBytes))
	}

	detailsStr := ""
	if len(logDetails) > 0 {
		detailsStr = fmt.Sprintf("Updated fields: %s", CsvString(logDetails))
	}

	if err := database.LogAdminActionWithTx(tx, adminEmail, "update_user", targetEmail, detailsStr); err != nil {
		logging.ErrorLogger.Printf("Failed to log admin action: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to log admin action")
	}

	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Failed to commit transaction: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit user update")
	}

	logging.InfoLogger.Printf("User updated: %s by %s", targetEmail, adminEmail)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "User updated successfully",
	})
}

// DeleteUser handles user deletion by admin
func DeleteUser(c echo.Context) error {
	adminEmail := auth.GetEmailFromToken(c)

	// Check admin privileges
	admin, err := models.GetUserByEmail(database.DB, adminEmail)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get admin user")
	}

	if !admin.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get target user's email
	targetEmail := c.Param("email")
	if targetEmail == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Email parameter required")
	}

	// Cannot delete self
	if targetEmail == adminEmail {
		return echo.NewHTTPError(http.StatusBadRequest, "Cannot delete your own account")
	}

	// Begin transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()

	// Get user's files
	rows, err := tx.Query("SELECT filename FROM file_metadata WHERE owner_email = ?", targetEmail)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to query user files: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve user's files")
	}

	var filenames []string
	for rows.Next() {
		var filename string
		if err := rows.Scan(&filename); err != nil {
			logging.ErrorLogger.Printf("Error scanning filename: %v", err)
			continue
		}
		filenames = append(filenames, filename)
	}
	rows.Close()

	// Delete user's files
	for _, filename := range filenames {
		if err := storage.Provider.RemoveObject(c.Request().Context(), filename, minio.RemoveObjectOptions{}); err != nil {
			logging.ErrorLogger.Printf("Failed to remove file %s from storage via provider: %v", filename, err)
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to delete user's file from storage: %s", filename))
		}
		_, err = tx.Exec("DELETE FROM file_metadata WHERE filename = ?", filename)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to delete file metadata for %s: %v", filename, err)
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Failed to delete file metadata for: %s", filename))
		}
	}

	// Delete user's shares
	_, err = tx.Exec("DELETE FROM file_shares WHERE owner_email = ?", targetEmail)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to delete user shares: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete user's file shares")
	}

	// Delete user record
	result, err := tx.Exec("DELETE FROM users WHERE email = ?", targetEmail)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to delete user record: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete user record")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		// This path is taken if the user does not exist.
		return echo.NewHTTPError(http.StatusNotFound, "User not found for deletion")
	}

	if err := database.LogAdminActionWithTx(tx, adminEmail, "delete_user", targetEmail, ""); err != nil {
		logging.ErrorLogger.Printf("Failed to log admin action: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to log admin action")
	}

	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Failed to commit transaction: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit user deletion transaction")
	}
	logging.InfoLogger.Printf("User deleted: %s by %s", targetEmail, adminEmail)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "User deleted successfully",
	})
}

// GetSystemStats returns system-wide statistics
func GetSystemStats(c echo.Context) error {
	adminEmail := auth.GetEmailFromToken(c)

	// Check admin privileges
	admin, err := models.GetUserByEmail(database.DB, adminEmail)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get admin user")
	}

	if !admin.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get total user count
	var userCount int
	err = database.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to count users: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve user statistics")
	}

	// Get pending approval count
	var pendingCount int
	err = database.DB.QueryRow("SELECT COUNT(*) FROM users WHERE is_approved = 0").Scan(&pendingCount)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to count pending users: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve user statistics")
	}

	// Get admin count
	var adminCount int
	err = database.DB.QueryRow("SELECT COUNT(*) FROM users WHERE is_admin = 1").Scan(&adminCount)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to count admin users: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve user statistics")
	}

	// Get total file count
	var fileCount int
	err = database.DB.QueryRow("SELECT COUNT(*) FROM file_metadata").Scan(&fileCount)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to count files: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file statistics")
	}

	// Get total storage used
	var totalStorage int64
	err = database.DB.QueryRow("SELECT SUM(size_bytes) FROM file_metadata").Scan(&totalStorage)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to sum storage: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve storage statistics")
	}
	if totalStorage < 0 { // Handle NULL result
		totalStorage = 0
	}

	// Get total shares
	var shareCount int
	err = database.DB.QueryRow("SELECT COUNT(*) FROM file_shares").Scan(&shareCount)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to count shares: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve share statistics")
	}

	// Get recent activity count
	var recentActivityCount int
	err = database.DB.QueryRow(
		"SELECT COUNT(*) FROM user_activity WHERE timestamp > datetime('now', '-24 hours')",
	).Scan(&recentActivityCount)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to count recent activity: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve activity statistics")
	}

	database.LogAdminAction(adminEmail, "view_system_stats", "", "")

	return c.JSON(http.StatusOK, map[string]interface{}{
		"users": map[string]interface{}{
			"total":   userCount,
			"pending": pendingCount,
			"admins":  adminCount,
		},
		"files": map[string]interface{}{
			"count":        fileCount,
			"totalSize":    totalStorage,
			"readableSize": formatBytes(totalStorage),
		},
		"shares": shareCount,
		"activity": map[string]interface{}{
			"last24h": recentActivityCount,
		},
		"system": map[string]interface{}{
			"version":     "1.0.0", // Hardcoded for now, could be moved to config
			"environment": c.Get("environment"),
		},
	})
}

// GetActivityLogs returns system activity logs
func GetActivityLogs(c echo.Context) error {
	adminEmail := auth.GetEmailFromToken(c)

	// Check admin privileges
	admin, err := models.GetUserByEmail(database.DB, adminEmail)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get admin user")
	}

	if !admin.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get query parameters
	limit := 100 // Default limit
	if limitStr := c.QueryParam("limit"); limitStr != "" {
		var err error
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit <= 0 {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid limit parameter")
		}
		// Cap maximum to prevent excessive load
		if limit > 1000 {
			limit = 1000
		}
	}

	// Optional filtering by user
	userFilter := c.QueryParam("user")
	userWhere := ""
	args := []interface{}{}

	if userFilter != "" {
		userWhere = " WHERE email = ?"
		args = append(args, userFilter)
	}

	// Query user activity
	query := fmt.Sprintf(`
		SELECT email, action, target, timestamp 
		FROM user_activity%s
		ORDER BY timestamp DESC
		LIMIT ?
	`, userWhere)

	args = append(args, limit)

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to query activity logs: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve activity logs")
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var (
			email     string
			action    string
			target    string
			timestamp time.Time
		)

		if err := rows.Scan(&email, &action, &target, &timestamp); err != nil {
			logging.ErrorLogger.Printf("Error scanning activity log row: %v", err)
			continue
		}

		logs = append(logs, map[string]interface{}{
			"email":     email,
			"action":    action,
			"target":    target,
			"timestamp": timestamp.Format(time.RFC3339),
		})
	}

	if err = rows.Err(); err != nil {
		logging.ErrorLogger.Printf("Error iterating activity log rows: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Error processing activity logs")
	}

	database.LogAdminAction(adminEmail, "view_activity_logs", "", "")

	return c.JSON(http.StatusOK, map[string]interface{}{
		"logs": logs,
	})
}
