package payments

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifyBTCPaySignature(t *testing.T) {
	secret := "webhook_secret_key"
	payload := []byte(`{"type":"InvoiceSettled","invoiceId":"abc"}`)

	// Generate valid signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	validSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	tests := []struct {
		name      string
		body      []byte
		sigHeader string
		secret    string
		want      bool
	}{
		{
			name:      "valid signature",
			body:      payload,
			sigHeader: validSig,
			secret:    secret,
			want:      true,
		},
		{
			name:      "invalid header prefix",
			body:      payload,
			sigHeader: hex.EncodeToString(mac.Sum(nil)),
			secret:    secret,
			want:      false,
		},
		{
			name:      "corrupted signature",
			body:      payload,
			sigHeader: validSig + "1",
			secret:    secret,
			want:      false,
		},
		{
			name:      "mismatched payload",
			body:      []byte(`{"type":"InvoiceSettled","invoiceId":"different"}`),
			sigHeader: validSig,
			secret:    secret,
			want:      false,
		},
		{
			name:      "mismatched secret",
			body:      payload,
			sigHeader: validSig,
			secret:    secret + "different",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VerifyBTCPaySignature(tt.body, tt.sigHeader, tt.secret)
			if got != tt.want {
				t.Errorf("VerifyBTCPaySignature() = %v, want %v", got, tt.want)
			}
		})
	}
}
