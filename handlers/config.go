package handlers

import (
	"net/http"

	"github.com/84adam/Arkfile/crypto"
	"github.com/labstack/echo/v4"
)

// GetArgon2Config returns the Argon2id parameters configuration from embedded data
// This ensures TypeScript and Go use the same parameters
func GetArgon2Config(c echo.Context) error {
	// Return the raw embedded JSON directly
	data := crypto.GetEmbeddedArgon2ParamsJSON()
	return c.JSONBlob(http.StatusOK, data)
}

// GetPasswordRequirements returns the password validation requirements from embedded data
// This ensures TypeScript and Go use the same validation rules
func GetPasswordRequirements(c echo.Context) error {
	// Return the raw embedded JSON directly
	data := crypto.GetEmbeddedPasswordRequirementsJSON()
	return c.JSONBlob(http.StatusOK, data)
}
