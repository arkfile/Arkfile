package handlers

import (
	"net/http"
	"os"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/storage"
)

// AdminVerifyStorage handles POST /api/admin/system/verify-storage
// Runs a full S3 round-trip test (upload, download, hash verify, delete)
// using the server's already-initialized storage provider.
// Requires admin JWT authentication.
func AdminVerifyStorage(c echo.Context) error {
	providerName := os.Getenv("STORAGE_PROVIDER")
	if providerName == "" {
		providerName = "generic-s3"
	}

	result := storage.RunVerification(providerName)

	if result.Verified {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Storage verification passed",
			"data":    result,
		})
	}

	return c.JSON(http.StatusInternalServerError, map[string]interface{}{
		"success": false,
		"message": "Storage verification failed",
		"data":    result,
	})
}
