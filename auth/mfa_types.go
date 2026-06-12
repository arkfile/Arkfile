package auth

import "time"

const (
	TOTPIssuer       = "Arkfile"
	TOTPDigits       = 6
	TOTPPeriod       = 30
	TOTPSkew         = 1 // Allow ±1 window (accepts current, previous, and next 30s windows)
	BackupCodeLength = 10
	BackupCodeCount  = 10
)

// Human-friendly backup code character set (excludes B/8, O/0, I/1, S/5, Z/2)
const BackupCodeCharset = "ACDEFGHJKLMNPQRTUVWXY34679"

// MFASetup represents enrollment material for a TOTP second factor.
type MFASetup struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	QRCodeImage string   `json:"qr_code_image"`
	BackupCodes []string `json:"backup_codes"`
	ManualEntry string   `json:"manual_entry"`
}

// MFAData represents stored MFA credential state for a user.
type MFAData struct {
	SecretEncrypted []byte `json:"credential_data"`
	Enabled         bool   `json:"enabled"`
	SetupCompleted  bool   `json:"setup_completed"`
	CreatedAt       time.Time
	LastUsed        *time.Time
}
