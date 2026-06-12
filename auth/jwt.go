package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/84adam/Arkfile/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
)

// JWT audience constants. These are checked at the validator (ParseTokenFunc)
// in addition to the per-tier signing-key separation.
const (
	AudienceMFA    = "arkfile-mfa"
	AudienceAPI    = "arkfile-api"
	AudienceExport = "arkfile-export"
	AudienceReset  = "arkfile-mfa-reset"
	Issuer         = "arkfile-auth"
)

// Echo is the Echo group with authentication middleware applied
var Echo *echo.Group

type Claims struct {
	Username    string `json:"username"`
	RequiresMFA bool   `json:"requires_mfa,omitempty"`
	jwt.RegisteredClaims
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

// GenerateTemporaryMFAToken creates a temporary JWT token that requires MFA completion.
// Signed with the temp-tier key; carries aud=arkfile-mfa and requires_mfa=true.
// Only valid at /api/mfa/{setup,verify,auth} via MFAJWTMiddleware.
func GenerateTemporaryMFAToken(username string) (string, time.Time, error) {
	tokenID := uuid.New().String()
	expirationTime := time.Now().Add(20 * time.Minute)

	claims := &Claims{
		Username:    username,
		RequiresMFA: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    Issuer,
			Audience:  []string{AudienceMFA},
			ID:        tokenID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(GetJWTTempPrivateKey())
	return tokenString, expirationTime, err
}

// GenerateTemporaryResetToken creates a short-lived reset-authorized temporary JWT token.
// Signed with the temp-tier key; carries aud=arkfile-mfa-reset.
func GenerateTemporaryResetToken(username string) (string, time.Time, error) {
	tokenID := uuid.New().String()
	expirationTime := time.Now().Add(15 * time.Minute)

	claims := &Claims{
		Username:    username,
		RequiresMFA: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    Issuer,
			Audience:  []string{AudienceReset},
			ID:        tokenID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(GetJWTTempPrivateKey())
	return tokenString, expirationTime, err
}

// GenerateFullAccessToken creates a full access JWT token after MFA validation.
// Signed with the full-tier key; carries aud=arkfile-api and requires_mfa=false.
// Valid at every JWTMiddleware-protected route.
func GenerateFullAccessToken(username string) (string, time.Time, error) {
	tokenID := uuid.New().String()
	expirationTime := time.Now().Add(utils.GetJWTTokenLifetime())

	claims := &Claims{
		Username:    username,
		RequiresMFA: false,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    Issuer,
			Audience:  []string{AudienceAPI},
			ID:        tokenID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(GetJWTFullPrivateKey())
	return tokenString, expirationTime, err
}

// parseTokenWithAudience builds a ParseTokenFunc that validates Ed25519
// signature with the given public key AND enforces the expected audience
// claim. Either failure mode produces a generic 401; the caller cannot
// distinguish "wrong signature" from "wrong audience" by error shape.
func parseTokenWithAudience(pubKey interface{}, expectedAudience string) func(c echo.Context, auth string) (interface{}, error) {
	return func(_ echo.Context, tokenString string) (interface{}, error) {
		parser := jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
			jwt.WithAudience(expectedAudience),
			jwt.WithIssuer(Issuer),
			jwt.WithExpirationRequired(),
		)
		token, err := parser.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
			return pubKey, nil
		})
		if err != nil {
			return nil, err
		}
		if !token.Valid {
			return nil, fmt.Errorf("invalid token")
		}
		return token, nil
	}
}

// JWTMiddleware validates full-access tokens (aud=arkfile-api). It verifies
// the signature against the full-tier public key and enforces audience and
// issuer at the parser layer. A temp-tier token (signed with the temp key,
// aud=arkfile-mfa) fails here in two ways: wrong signing key AND wrong
// audience. Either is enough; both is defense in depth.
func JWTMiddleware() echo.MiddlewareFunc {
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(Claims)
		},
		ParseTokenFunc: parseTokenWithAudience(GetJWTFullPublicKey(), AudienceAPI),
		ErrorHandler: func(c echo.Context, err error) error {
			return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
		},
	}
	return echojwt.WithConfig(config)
}

// MFAJWTMiddleware validates temporary MFA-handoff tokens (aud=arkfile-mfa).
// Used only by /api/mfa/{setup,verify,auth}. A full-tier token fails the
// signing-key check AND the audience check.
func MFAJWTMiddleware() echo.MiddlewareFunc {
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(Claims)
		},
		ParseTokenFunc: parseTokenWithAudience(GetJWTTempPublicKey(), AudienceMFA),
		ErrorHandler: func(c echo.Context, err error) error {
			return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
		},
	}
	return echojwt.WithConfig(config)
}

// RequireFullJWT is defense-in-depth: even though JWTMiddleware enforces the
// aud=arkfile-api audience, this middleware also asserts requires_mfa=false
// and re-verifies the audience claim. Protects against a future regression
// that loosens the validator's audience enforcement.
//
// Wired onto every protected group: mfaProtectedGroup, pendingAllowedGroup,
// adminGroup, and devTestAdminGroup.
func RequireFullJWT(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		userToken, ok := c.Get("user").(*jwt.Token)
		if !ok || userToken == nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
		}
		claims, ok := userToken.Claims.(*Claims)
		if !ok {
			return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
		}
		if claims.RequiresMFA {
			return echo.NewHTTPError(http.StatusForbidden, "Full authentication required")
		}
		if !slices.Contains(claims.Audience, AudienceAPI) {
			return echo.NewHTTPError(http.StatusForbidden, "Token audience does not permit this route")
		}
		return next(c)
	}
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

// RequiresMFAFromToken returns whether the token in the request context
// carries the requires_mfa=true flag. Safe against missing/malformed
// context entries: returns false rather than panicking.
func RequiresMFAFromToken(c echo.Context) bool {
	user, ok := c.Get("user").(*jwt.Token)
	if !ok || user == nil {
		return false
	}
	claims, ok := user.Claims.(*Claims)
	if !ok {
		return false
	}
	return claims.RequiresMFA
}

// GetClaimsFromContext returns parsed claims from context or nil
func GetClaimsFromContext(c echo.Context) (*Claims, bool) {
	user, ok := c.Get("user").(*jwt.Token)
	if !ok || user == nil {
		return nil, false
	}
	claims, ok := user.Claims.(*Claims)
	return claims, ok
}
