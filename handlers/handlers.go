package handlers

import (
	"database/sql"
	"errors" // Import errors package
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
	"github.com/84adam/arkfile/storage"
	"github.com/84adam/arkfile/utils"
)

// Echo is the global echo instance used for routing
var Echo *echo.Echo

// Register handles user registration
func Register(c echo.Context) error {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	// Validate email
	if !strings.Contains(request.Email, "@") {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid email format")
	}

	// Validate password complexity using the centralized function
	if err := utils.ValidatePasswordComplexity(request.Password); err != nil {
		// Return the specific error message from the validator
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Create user
	user, err := models.CreateUser(database.DB, request.Email, request.Password)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return echo.NewHTTPError(http.StatusConflict, "Email already registered")
		}
		logging.ErrorLogger.Printf("Failed to create user: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create user")
	}

	database.LogUserAction(request.Email, "registered", "")
	logging.InfoLogger.Printf("User registered: %s", request.Email)

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"message": "Account created successfully",
		"status": map[string]interface{}{
			"is_approved": user.IsApproved,
			"is_admin":    user.IsAdmin,
		},
	})
}

// Login handles user authentication
func Login(c echo.Context) error {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	// Get user
	user, err := models.GetUserByEmail(database.DB, request.Email)
	// Check for sql.ErrNoRows OR the specific error string from GetUserByEmail
	if errors.Is(err, sql.ErrNoRows) || (err != nil && err.Error() == "user not found") {
		// Optional: time.Sleep(100 * time.Millisecond) // Mitigate timing attacks
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error during login: %v", err)
		// Do not reveal specific internal errors for failed login
		return echo.NewHTTPError(http.StatusInternalServerError, "Login failed")
	}

	// Verify password
	if !user.VerifyPassword(request.Password) {
		// Optional: time.Sleep(100 * time.Millisecond)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	// Generate JWT token
	token, err := auth.GenerateToken(request.Email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate token: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Login failed")
	}

	// Generate refresh token
	refreshToken, err := models.CreateRefreshToken(database.DB, request.Email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate refresh token: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Login failed")
	}

	database.LogUserAction(request.Email, "logged in", "")
	logging.InfoLogger.Printf("User logged in: %s", request.Email)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"token":        token,
		"refreshToken": refreshToken,
		"user": map[string]interface{}{
			"email":           user.Email,
			"is_approved":     user.IsApproved,
			"is_admin":        user.IsAdmin,
			"total_storage":   user.TotalStorage,
			"storage_limit":   user.StorageLimit,
			"storage_used_pc": float64(user.TotalStorage) / float64(user.StorageLimit) * 100,
		},
	})
}

// UploadFile handles file uploads
func UploadFile(c echo.Context) error {
	email := auth.GetEmailFromToken(c)

	// Get user for storage checks
	user, err := models.GetUserByEmail(database.DB, email)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user details")
	}

	var request struct {
		Filename     string `json:"filename"`
		Data         string `json:"data"`
		PasswordHint string `json:"passwordHint"`
		PasswordType string `json:"passwordType"`
		SHA256Sum    string `json:"sha256sum"`
	}

	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	// Validate SHA-256 hash format
	if len(request.SHA256Sum) != 64 || !utils.IsHexString(request.SHA256Sum) {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid SHA-256 hash")
	}

	// Validate password type
	if request.PasswordType != "account" && request.PasswordType != "custom" {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid password type")
	}

	// Check if file size would exceed user's limit
	fileSize := int64(len(request.Data))
	if !user.CheckStorageAvailable(fileSize) {
		return echo.NewHTTPError(http.StatusForbidden, "Storage limit would be exceeded")
	}

	// Start transaction for atomic storage update
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback() // Rollback if not committed

	// Store file in object storage backend using storage.Provider
	_, err = storage.Provider.PutObject(
		c.Request().Context(),
		request.Filename, // bucketName is handled by the provider
		strings.NewReader(request.Data),
		fileSize,
		minio.PutObjectOptions{ContentType: "application/octet-stream"},
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to upload file: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to upload file")
	}

	// Store metadata in database
	_, err = tx.Exec(
		"INSERT INTO file_metadata (filename, owner_email, password_hint, password_type, sha256sum, size_bytes) VALUES (?, ?, ?, ?, ?, ?)",
		request.Filename, email, request.PasswordHint, request.PasswordType, request.SHA256Sum, fileSize,
	)
	if err != nil {
		// If metadata storage fails, delete the uploaded file using storage.Provider
		storage.Provider.RemoveObject(c.Request().Context(), request.Filename, minio.RemoveObjectOptions{})
		logging.ErrorLogger.Printf("Failed to store file metadata: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process file")
	}

	// Update user's storage usage
	if err := user.UpdateStorageUsage(tx, fileSize); err != nil {
		logging.ErrorLogger.Printf("Failed to update storage usage: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update storage usage")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Failed to commit transaction: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to complete upload")
	}

	database.LogUserAction(email, "uploaded", request.Filename)
	logging.InfoLogger.Printf("File uploaded: %s by %s (size: %d bytes)", request.Filename, email, fileSize)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "File uploaded successfully",
		"storage": map[string]interface{}{
			"total_bytes":     user.TotalStorage + fileSize,
			"limit_bytes":     user.StorageLimit,
			"available_bytes": user.StorageLimit - (user.TotalStorage + fileSize),
		},
	})
}

// DownloadFile handles file downloads
func DownloadFile(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	filename := c.Param("filename")

	// Verify file ownership
	var ownerEmail string
	err := database.DB.QueryRow(
		"SELECT owner_email FROM file_metadata WHERE filename = ?",
		filename,
	).Scan(&ownerEmail)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error during download: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	if ownerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Access denied")
	}

	// Get file metadata
	var fileMetadata struct {
		PasswordHint string
		PasswordType string
		SHA256Sum    string
	}
	err = database.DB.QueryRow(
		"SELECT password_hint, password_type, sha256sum FROM file_metadata WHERE filename = ?",
		filename,
	).Scan(&fileMetadata.PasswordHint, &fileMetadata.PasswordType, &fileMetadata.SHA256Sum)

	// Get file from object storage backend using storage.Provider
	object, err := storage.Provider.GetObject(
		c.Request().Context(),
		filename, // bucketName is handled by the provider
		minio.GetObjectOptions{},
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to retrieve file via provider: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file")
	}
	defer object.Close()

	data, err := io.ReadAll(object)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to read file: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to read file")
	}

	database.LogUserAction(email, "downloaded", filename)
	logging.InfoLogger.Printf("File downloaded: %s by %s", filename, email)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data":         string(data),
		"passwordHint": fileMetadata.PasswordHint,
		"passwordType": fileMetadata.PasswordType,
		"sha256sum":    fileMetadata.SHA256Sum,
	})
}

// ListFiles returns a list of files owned by the user
func ListFiles(c echo.Context) error {
	email := auth.GetEmailFromToken(c)

	rows, err := database.DB.Query(`
		SELECT filename, password_hint, password_type, sha256sum, size_bytes, upload_date 
		FROM file_metadata 
		WHERE owner_email = ?
		ORDER BY upload_date DESC
	`, email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to list files: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve files")
	}
	defer rows.Close()

	var files []map[string]interface{}
	for rows.Next() {
		var file struct {
			Filename     string
			PasswordHint string
			PasswordType string
			SHA256Sum    string
			SizeBytes    int64
			UploadDate   string
		}

		if err := rows.Scan(&file.Filename, &file.PasswordHint, &file.PasswordType, &file.SHA256Sum, &file.SizeBytes, &file.UploadDate); err != nil {
			logging.ErrorLogger.Printf("Error scanning file row: %v", err)
			continue
		}

		files = append(files, map[string]interface{}{
			"filename":      file.Filename,
			"passwordHint":  file.PasswordHint,
			"passwordType":  file.PasswordType,
			"sha256sum":     file.SHA256Sum,
			"size_bytes":    file.SizeBytes,
			"size_readable": formatBytes(file.SizeBytes),
			"uploadDate":    file.UploadDate,
		})
	}

	// Get user's storage information
	user, err := models.GetUserByEmail(database.DB, email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get user storage info: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get storage info")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"files": files,
		"storage": map[string]interface{}{
			"total_bytes":        user.TotalStorage,
			"total_readable":     formatBytes(user.TotalStorage),
			"limit_bytes":        user.StorageLimit,
			"limit_readable":     formatBytes(user.StorageLimit),
			"available_bytes":    user.StorageLimit - user.TotalStorage,
			"available_readable": formatBytes(user.StorageLimit - user.TotalStorage),
			"usage_percent":      float64(user.TotalStorage) / float64(user.StorageLimit) * 100,
		},
	})
}

// formatBytes converts bytes to human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// DeleteFile handles file deletion
func DeleteFile(c echo.Context) error {
	email := auth.GetEmailFromToken(c)
	filename := c.Param("filename")

	// Begin transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction")
	}
	defer tx.Rollback() // Rollback if not committed

	// Verify file ownership and get file size
	var ownerEmail string
	var fileSize int64
	err = tx.QueryRow(
		"SELECT owner_email, size_bytes FROM file_metadata WHERE filename = ?",
		filename,
	).Scan(&ownerEmail, &fileSize)

	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	} else if err != nil {
		logging.ErrorLogger.Printf("Database error checking file ownership: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
	}

	// Verify ownership
	if ownerEmail != email {
		return echo.NewHTTPError(http.StatusForbidden, "Not authorized to delete this file")
	}

	// Remove from object storage using storage.Provider
	err = storage.Provider.RemoveObject(c.Request().Context(), filename, minio.RemoveObjectOptions{})
	if err != nil {
		logging.ErrorLogger.Printf("Failed to remove file from storage via provider: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete file from storage")
	}

	// Delete metadata from database
	_, err = tx.Exec("DELETE FROM file_metadata WHERE filename = ?", filename)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to delete file metadata: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete file metadata")
	}

	// Update user's storage usage (reduce by file size)
	user, err := models.GetUserByEmail(database.DB, email)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get user: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update storage usage")
	}

	// Use negative value to reduce storage usage
	if err := user.UpdateStorageUsage(tx, -fileSize); err != nil {
		logging.ErrorLogger.Printf("Failed to update storage usage: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update storage usage")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Failed to commit transaction: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to complete file deletion")
	}

	database.LogUserAction(email, "deleted", filename)
	logging.InfoLogger.Printf("File deleted: %s by %s", filename, email)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "File deleted successfully",
		"storage": map[string]interface{}{
			// Use the user.TotalStorage already updated in memory by UpdateStorageUsage
			"total_bytes": user.TotalStorage,
			"limit_bytes": user.StorageLimit,
			// Calculate available based on the updated total
			"available_bytes": user.StorageLimit - user.TotalStorage,
		},
	})
}
