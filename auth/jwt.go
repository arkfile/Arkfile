package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/84adam/Arkfile/utils"
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

func GenerateToken(username string) (string, time.Time, error) {
	// Generate a unique token ID
	tokenID := uuid.New().String()
	expirationTime := time.Now().Add(utils.GetJWTTokenLifetime())

	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime), // Token expires based on environment config
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "arkfile-auth",          // Add issuer claim
			Audience:  []string{"arkfile-api"}, // Add audience claim
			ID:        tokenID,                 // Add jti claim
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	// Use Ed25519 private key for signing
	tokenString, err := token.SignedString(GetJWTPrivateKey())
	return tokenString, expirationTime, err
}

func JWTMiddleware() echo.MiddlewareFunc {
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(Claims)
		},
		// Use Ed25519 public key for validation
		SigningKey:    GetJWTPublicKey(),
		SigningMethod: jwt.SigningMethodEdDSA.Alg(),
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
func GenerateTemporaryTOTPToken(username string) (string, time.Time, error) {
	tokenID := uuid.New().String()
	expirationTime := time.Now().Add(5 * time.Minute)

	claims := &Claims{
		Username:     username,
		RequiresTOTP: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime), // 5 minute expiry
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "arkfile-auth",
			Audience:  []string{"arkfile-totp"},
			ID:        tokenID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(GetJWTPrivateKey())
	return tokenString, expirationTime, err
}

// GenerateFullAccessToken creates a full access JWT token after TOTP validation
func GenerateFullAccessToken(username string) (string, time.Time, error) {
	tokenID := uuid.New().String()
	expirationTime := time.Now().Add(utils.GetJWTTokenLifetime())

	claims := &Claims{
		Username:     username,
		RequiresTOTP: false,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime), // Configurable expiry time
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "arkfile-auth",
			Audience:  []string{"arkfile-api"},
			ID:        tokenID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(GetJWTPrivateKey())
	return tokenString, expirationTime, err
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
		SigningKey:    GetJWTPublicKey(),
		SigningMethod: jwt.SigningMethodEdDSA.Alg(),
		ErrorHandler: func(c echo.Context, err error) error {
			return echo.NewHTTPError(401, "Unauthorized")
		},
	}
	return echojwt.WithConfig(config)
}
