package auth

import (
    "os"
    "time"

    "github.com/golang-jwt/jwt"
    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
)

type Claims struct {
    Email string `json:"email"`
    jwt.StandardClaims
}

func GenerateToken(email string) (string, error) {
    claims := &Claims{
        Email: email,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: time.Now().Add(time.Hour * 72).Unix(), // Token expires in 72 hours
            IssuedAt:  time.Now().Unix(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

func JWTMiddleware() echo.MiddlewareFunc {
    config := middleware.JWTConfig{
        Claims:     &Claims{},
        SigningKey: []byte(os.Getenv("JWT_SECRET")),
        ErrorHandler: func(err error) error {
            return echo.NewHTTPError(401, "Unauthorized")
        },
    }
    return middleware.JWTWithConfig(config)
}

func GetEmailFromToken(c echo.Context) string {
    user := c.Get("user").(*jwt.Token)
    claims := user.Claims.(*Claims)
    return claims.Email
}
