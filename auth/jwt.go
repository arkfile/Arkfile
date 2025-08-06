package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/84adam/arkfile/config" // Import config package
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
)

// Echo is the Echo group with authentication middleware applied
var Echo *echo.Group

type Claims struct {
	Username     string `json:"username"`
	RequiresTOTP bool   `json:"requires_totp,omitempty"`
	jwt.RegisteredClaims
}

func GenerateToken(username string) (string, error) {
	// Generate a unique token ID
	tokenID := uuid.New().String()

	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)), // Token expires in 24 hours
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "arkfile-auth",          // Add issuer claim
			Audience:  []string{"arkfile-api"}, // Add audience claim
			ID:        tokenID,                 // Add jti claim
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Use JWTSecret from loaded config
	return token.SignedString([]byte(config.GetConfig().Security.JWTSecret))
}

func JWTMiddleware() echo.MiddlewareFunc {
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(Claims)
		},
		// Use JWTSecret from loaded config
		SigningKey: []byte(config.GetConfig().Security.JWTSecret),
		ErrorHandler: func(c echo.Context, err error) error {
			return echo.NewHTTPError(401, "Unauthorized")
		},
	}
	return echojwt.WithConfig(config)
}

func GetUsernameFromToken(c echo.Context) string {
	user, ok := c.Get("user").(*jwt.Token)
	if !ok || user == nil {
		return ""
	}
	claims, ok := user.Claims.(*Claims)
	if !ok {
		return ""
	}
	return claims.Username
}

// GenerateRefreshToken creates a cryptographically secure random string to be used as a refresh token.
// It aims for approximately 256 bits of entropy.
func GenerateRefreshToken() (string, error) {
	b := make([]byte, 32) // 32 bytes = 256 bits
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// HashToken generates a SHA-256 hash of a token string.
// The raw token should not be stored; only its hash.
func HashToken(token string) (string, error) {
	hasher := sha256.New()
	_, err := hasher.Write([]byte(token))
	if err != nil { // Should be practically impossible for sha256.Write to error with non-nil hasher
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// GenerateTemporaryTOTPToken creates a temporary JWT token that requires TOTP completion
func GenerateTemporaryTOTPToken(username string) (string, error) {
	tokenID := uuid.New().String()

	claims := &Claims{
		Username:     username,
		RequiresTOTP: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)), // 5 minute expiry
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "arkfile-auth",
			Audience:  []string{"arkfile-totp"},
			ID:        tokenID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.GetConfig().Security.JWTSecret))
}

// GenerateFullAccessToken creates a full access JWT token after TOTP validation
func GenerateFullAccessToken(username string) (string, error) {
	tokenID := uuid.New().String()

	claims := &Claims{
		Username:     username,
		RequiresTOTP: false,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)), // 24 hour expiry
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "arkfile-auth",
			Audience:  []string{"arkfile-api"},
			ID:        tokenID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.GetConfig().Security.JWTSecret))
}

// RequiresTOTPFromToken checks if the token requires TOTP completion
func RequiresTOTPFromToken(c echo.Context) bool {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*Claims)
	return claims.RequiresTOTP
}

// TOTPJWTMiddleware creates middleware that only allows TOTP-related operations
func TOTPJWTMiddleware() echo.MiddlewareFunc {
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(Claims)
		},
		SigningKey: []byte(config.GetConfig().Security.JWTSecret),
		ErrorHandler: func(c echo.Context, err error) error {
			return echo.NewHTTPError(401, "Unauthorized")
		},
	}
	return echojwt.WithConfig(config)
}
