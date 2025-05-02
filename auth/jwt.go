package auth

import (
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
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func GenerateToken(email string) (string, error) {
	// Generate a unique token ID
	tokenID := uuid.New().String()

	claims := &Claims{
		Email: email,
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

func GetEmailFromToken(c echo.Context) string {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*Claims)
	return claims.Email
}
