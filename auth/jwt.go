package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strings"
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

// parseTokenWithAudience builds a ParseTokenFunc that validates the Ed25519
// signature against any currently accepted verification key for the tier AND
// enforces the expected audience claim. The key set is resolved per request
// via keysGetter so that a rotation (which adds a new active key and keeps the
// previous one for the overlap window) takes effect without re-wiring the
// middleware. Either failure mode produces a generic 401; the caller cannot
// distinguish "wrong signature" from "wrong audience" by error shape.
func parseTokenWithAudience(keysGetter func() []ed25519.PublicKey, expectedAudience string) func(c echo.Context, auth string) (interface{}, error) {
	return func(_ echo.Context, tokenString string) (interface{}, error) {
		parser := jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
			jwt.WithAudience(expectedAudience),
			jwt.WithIssuer(Issuer),
			jwt.WithExpirationRequired(),
		)
		token, err := parseEdDSAAnyKey(parser, tokenString, keysGetter())
		if err != nil {
			return nil, err
		}
		if !token.Valid {
			return nil, fmt.Errorf("invalid token")
		}
		return token, nil
	}
}

// ParseEdDSAClaimsAnyFullKey parses tokenString into the provided claims using
// the supplied parser, trying every full-tier verification key. Exposed for
// callers outside the auth package (e.g. export-token validation) that need
// rotation-aware verification with custom claim types. The parser should carry
// any required audience/issuer/expiry options.
func ParseEdDSAClaimsAnyFullKey(parser *jwt.Parser, tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	var lastErr error
	for _, pk := range GetJWTFullVerificationKeys() {
		pkCopy := pk
		token, err := parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			return pkCopy, nil
		})
		if err == nil && token.Valid {
			return token, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("invalid token")
	}
	return nil, lastErr
}

// parseEdDSAAnyKey attempts to parse and validate the token against each
// provided public key, returning on the first success. It returns the last
// error encountered if no key validates.
func parseEdDSAAnyKey(parser *jwt.Parser, tokenString string, pubKeys []ed25519.PublicKey) (*jwt.Token, error) {
	var lastErr error
	for _, pk := range pubKeys {
		pkCopy := pk
		token, err := parser.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
			return pkCopy, nil
		})
		if err == nil && token.Valid {
			return token, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("invalid token")
	}
	return nil, lastErr
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
		ParseTokenFunc: parseTokenWithAudience(GetJWTFullVerificationKeys, AudienceAPI),
		ErrorHandler: func(c echo.Context, err error) error {
			return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
		},
	}
	return echojwt.WithConfig(config)
}

// stripBearerPrefix returns the JWT string from an Authorization header value.
func stripBearerPrefix(auth string) string {
	auth = strings.TrimSpace(auth)
	if len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return auth
}

// ResetJWTMiddleware validates reset-authorized temporary tokens (aud=arkfile-mfa-reset).
// Used by /api/mfa/reset after backup-code recovery (path B).
func ResetJWTMiddleware() echo.MiddlewareFunc {
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(Claims)
		},
		ParseTokenFunc: parseTokenWithAudience(GetJWTTempVerificationKeys, AudienceReset),
		ErrorHandler: func(c echo.Context, err error) error {
			return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
		},
	}
	return echojwt.WithConfig(config)
}

// MFAResetJWTMiddleware accepts either a full-tier token (aud=arkfile-api,
// requires_mfa=false) for self-service reset with a backup code, or a
// reset-tier token (aud=arkfile-mfa-reset) issued by recover-with-backup-code.
func MFAResetJWTMiddleware() echo.MiddlewareFunc {
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(Claims)
		},
		ParseTokenFunc: func(_ echo.Context, auth string) (interface{}, error) {
			tokenString := stripBearerPrefix(auth)
			parser := jwt.NewParser(
				jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
				jwt.WithIssuer(Issuer),
				jwt.WithExpirationRequired(),
			)

			if fullToken, err := parseEdDSAAnyKey(parser, tokenString, GetJWTFullVerificationKeys()); err == nil && fullToken.Valid {
				claims, ok := fullToken.Claims.(*Claims)
				if ok && !claims.RequiresMFA && slices.Contains(claims.Audience, AudienceAPI) {
					return fullToken, nil
				}
			}

			resetParser := jwt.NewParser(
				jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
				jwt.WithAudience(AudienceReset),
				jwt.WithIssuer(Issuer),
				jwt.WithExpirationRequired(),
			)
			if resetToken, err := parseEdDSAAnyKey(resetParser, tokenString, GetJWTTempVerificationKeys()); err == nil && resetToken.Valid {
				return resetToken, nil
			}

			return nil, fmt.Errorf("invalid token")
		},
		ErrorHandler: func(c echo.Context, err error) error {
			return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
		},
	}
	return echojwt.WithConfig(config)
}

// MFAJWTMiddleware validates temporary MFA-handoff tokens (aud=arkfile-mfa).
// Used only by /api/mfa/{setup,verify,auth,recover-with-backup-code}. A full-tier
// token fails the signing-key check AND the audience check.
func MFAJWTMiddleware() echo.MiddlewareFunc {
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(Claims)
		},
		ParseTokenFunc: parseTokenWithAudience(GetJWTTempVerificationKeys, AudienceMFA),
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
