package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"github.com/labstack/echo/v4"
)

// Argon2Params represents the Argon2id parameters configuration
type Argon2Params struct {
	Memory      uint32 `json:"memory"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	SaltLength  uint32 `json:"saltLength"`
	KeyLength   uint32 `json:"keyLength"`
}

// PasswordRequirements represents the password validation configuration
type PasswordRequirements struct {
	Account PasswordContext `json:"account"`
	Share   PasswordContext `json:"share"`
	Custom  PasswordContext `json:"custom"`
}

// PasswordContext represents requirements for a specific password context
type PasswordContext struct {
	MinLength        int     `json:"min_length"`
	MinEntropy       float64 `json:"min_entropy"`
	RequireUppercase bool    `json:"require_uppercase"`
	RequireLowercase bool    `json:"require_lowercase"`
	RequireDigit     bool    `json:"require_digit"`
	RequireSpecial   bool    `json:"require_special"`
}

// GetArgon2Config returns the Argon2id parameters configuration
// This ensures TypeScript and Go use the same parameters
func GetArgon2Config(c echo.Context) error {
	configPath := filepath.Join("config", "argon2id-params.json")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to load Argon2id configuration",
		})
	}

	var params Argon2Params
	if err := json.Unmarshal(data, &params); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to parse Argon2id configuration",
		})
	}

	return c.JSON(http.StatusOK, params)
}

// GetPasswordRequirements returns the password validation requirements
// This ensures TypeScript and Go use the same validation rules
func GetPasswordRequirements(c echo.Context) error {
	configPath := filepath.Join("config", "password-requirements.json")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to load password requirements configuration",
		})
	}

	var requirements PasswordRequirements
	if err := json.Unmarshal(data, &requirements); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to parse password requirements configuration",
		})
	}

	return c.JSON(http.StatusOK, requirements)
}
