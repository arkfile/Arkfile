package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7" // Import minio for options

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
	"github.com/84adam/arkfile/storage"
)

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
			continue
		}

		lastLoginStr := ""
		if lastLogin.Valid {
			lastLoginStr = lastLogin.Time.Format(time.RFC3339)
		}

		users = append(users, map[string]interface{}{
			"email":                email,
			"isApproved":           isApproved,
			"isAdmin":              isAdmin,
			"storageLimit":         storageLimit,
			"storageLimitReadable": formatBytes(storageLimit),
			"totalStorage":         totalStorage,
			"totalStorageReadable": formatBytes(totalStorage),
			"usagePercent":         float64(totalStorage) / float64(storageLimit) * 100,
			"registrationDate":     registrationDate.Format(time.RFC3339),
			"lastLogin":            lastLoginStr,
		})
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

	// Parse update data
	var request struct {
		IsApproved   *bool  `json:"isApproved"`
		IsAdmin      *bool  `json:"isAdmin"`
		StorageLimit *int64 `json:"storageLimit"`
	}
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	// Update user fields
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback()

	// Check user exists
	var exists bool
	err = tx.QueryRow("SELECT 1 FROM users WHERE email = ?", targetEmail).Scan(&exists)
	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	} else if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify user")
	}

	// Update approval status if provided
	if request.IsApproved != nil {
		_, err = tx.Exec("UPDATE users SET is_approved = ? WHERE email = ?", *request.IsApproved, targetEmail)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to update approval status: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update approval status")
		}

		action := "approve"
		if !*request.IsApproved {
			action = "revoke approval"
		}
		database.LogAdminAction(adminEmail, action, targetEmail, "")
	}

	// Update admin status if provided
	if request.IsAdmin != nil {
		_, err = tx.Exec("UPDATE users SET is_admin = ? WHERE email = ?", *request.IsAdmin, targetEmail)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to update admin status: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update admin status")
		}

		action := "grant admin"
		if !*request.IsAdmin {
			action = "revoke admin"
		}
		database.LogAdminAction(adminEmail, action, targetEmail, "")
	}

	// Update storage limit if provided
	if request.StorageLimit != nil {
		if *request.StorageLimit <= 0 {
			return echo.NewHTTPError(http.StatusBadRequest, "Storage limit must be positive")
		}

		_, err = tx.Exec("UPDATE users SET storage_limit_bytes = ? WHERE email = ?", *request.StorageLimit, targetEmail)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to update storage limit: %v", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update storage limit")
		}

		database.LogAdminAction(adminEmail, "update_storage_limit", targetEmail,
			fmt.Sprintf("New limit: %d bytes", *request.StorageLimit))
	}

	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Failed to commit transaction: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update user")
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
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process user files")
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
		// Remove from storage using storage.Provider
		if err := storage.Provider.RemoveObject(c.Request().Context(), filename, minio.RemoveObjectOptions{}); err != nil {
			logging.ErrorLogger.Printf("Failed to remove file %s from storage via provider: %v", filename, err)
			// Continue anyway - we want to delete the user even if some files can't be removed (Unchanged logic)
		}

		// Delete file metadata
		_, err = tx.Exec("DELETE FROM file_metadata WHERE filename = ?", filename)
		if err != nil {
			logging.ErrorLogger.Printf("Failed to delete file metadata for %s: %v", filename, err)
			// Continue anyway
		}
	}

	// Delete user's shares
	_, err = tx.Exec("DELETE FROM file_shares WHERE owner_email = ?", targetEmail)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to delete user shares: %v", err)
		// Continue anyway
	}

	// Delete user record
	result, err := tx.Exec("DELETE FROM users WHERE email = ?", targetEmail)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to delete user record: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete user")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Failed to commit transaction: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to complete user deletion")
	}

	database.LogAdminAction(adminEmail, "delete_user", targetEmail, "")
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
