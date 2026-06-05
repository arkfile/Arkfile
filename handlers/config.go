package handlers

import (
	"net/http"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/crypto"
	"github.com/labstack/echo/v4"
)

// GetOpaqueConfig returns the OPAQUE server identity (idS) bound into the
// protocol transcript. The browser and CLI clients fetch this so all OPAQUE
// participants use the exact same idS bytes; a mismatch breaks authentication.
func GetOpaqueConfig(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"server_id": auth.OpaqueServerID(),
	})
}

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

// GetChunkingConfig returns the chunking parameters configuration from embedded data
// This ensures TypeScript and Go use the same chunk sizes, envelope format, and AES-GCM parameters
func GetChunkingConfig(c echo.Context) error {
	// Return the raw embedded JSON directly
	data := crypto.GetEmbeddedChunkingParamsJSON()
	return c.JSONBlob(http.StatusOK, data)
}

// GetVersion returns the current Arkfile application version
func GetVersion(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"version": config.Version,
	})
}
