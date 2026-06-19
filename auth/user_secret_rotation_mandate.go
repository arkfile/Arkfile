package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	UserSecretRotationMandatePurpose = "user-secret-master-rotation"
	UserSecretRotationMandateTTL     = 10 * time.Minute
)

// UserSecretRotationMandatePayload is the signed authorization for offline user-secret master rotation.
type UserSecretRotationMandatePayload struct {
	Purpose       string `json:"purpose"`
	AdminUsername string `json:"admin_username"`
	Nonce         string `json:"nonce"`
	IssuedAt      int64  `json:"issued_at"`
	ExpiresAt     int64  `json:"expires_at"`
}

// IssueUserSecretRotationMandate records a single-use mandate and returns a signed blob for offline apply.
func IssueUserSecretRotationMandate(db *sql.DB, adminUsername string) (mandate string, expiresAt time.Time, err error) {
	if adminUsername == "" {
		return "", time.Time{}, fmt.Errorf("admin username is required")
	}
	if err := LoadJWTFullKeys(); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to load JWT signing keys: %w", err)
	}

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate mandate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	now := time.Now().UTC()
	expiresAt = now.Add(UserSecretRotationMandateTTL)

	_, err = db.Exec(`
		INSERT INTO user_secret_rotation_mandates (nonce, admin_username, expires_at)
		VALUES (?, ?, ?)`,
		nonce, adminUsername, expiresAt,
	)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to store rotation mandate: %w", err)
	}

	payload := UserSecretRotationMandatePayload{
		Purpose:       UserSecretRotationMandatePurpose,
		AdminUsername: adminUsername,
		Nonce:         nonce,
		IssuedAt:      now.Unix(),
		ExpiresAt:     expiresAt.Unix(),
	}

	mandate, err = signUserSecretRotationMandate(payload, GetJWTFullPrivateKey())
	if err != nil {
		return "", time.Time{}, err
	}
	return mandate, expiresAt, nil
}

// VerifyUserSecretRotationMandate validates the mandate signature and payload fields.
func VerifyUserSecretRotationMandate(mandate string, publicKey ed25519.PublicKey) (*UserSecretRotationMandatePayload, error) {
	payload, err := parseSignedUserSecretRotationMandate(mandate, publicKey)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if payload.Purpose != UserSecretRotationMandatePurpose {
		return nil, fmt.Errorf("invalid mandate purpose")
	}
	if payload.Nonce == "" || payload.AdminUsername == "" {
		return nil, fmt.Errorf("invalid mandate payload")
	}
	if now.Unix() > payload.ExpiresAt {
		return nil, fmt.Errorf("rotation mandate expired")
	}
	return payload, nil
}

// ConsumeUserSecretRotationMandate marks a mandate nonce as used.
func ConsumeUserSecretRotationMandate(db *sql.DB, nonce string) error {
	res, err := db.Exec(`
		UPDATE user_secret_rotation_mandates
		SET consumed_at = CURRENT_TIMESTAMP
		WHERE nonce = ? AND consumed_at IS NULL AND expires_at > CURRENT_TIMESTAMP`,
		nonce,
	)
	if err != nil {
		return fmt.Errorf("failed to consume rotation mandate: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows != 1 {
		return fmt.Errorf("rotation mandate is invalid, expired, or already consumed")
	}
	return nil
}

func signUserSecretRotationMandate(payload UserSecretRotationMandatePayload, privateKey ed25519.PrivateKey) (string, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal mandate payload: %w", err)
	}
	sig := ed25519.Sign(privateKey, payloadJSON)
	return base64.RawURLEncoding.EncodeToString(payloadJSON) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

func parseSignedUserSecretRotationMandate(mandate string, publicKey ed25519.PublicKey) (*UserSecretRotationMandatePayload, error) {
	parts := strings.Split(mandate, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid mandate format")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid mandate payload encoding: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid mandate signature encoding: %w", err)
	}
	if !ed25519.Verify(publicKey, payloadJSON, sig) {
		return nil, fmt.Errorf("invalid mandate signature")
	}
	var payload UserSecretRotationMandatePayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("invalid mandate payload: %w", err)
	}
	return &payload, nil
}
