package payments

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func VerifyBTCPaySignature(body []byte, sigHeader string, secret string) bool {
	if !strings.HasPrefix(sigHeader, "sha256=") {
		return false
	}
	hexSig := sigHeader[7:]
	expectedSig, err := hex.DecodeString(hexSig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	computedSig := mac.Sum(nil)
	return hmac.Equal(computedSig, expectedSig)
}
