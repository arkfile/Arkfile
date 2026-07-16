package auth

import (
	"encoding/base64"

	"github.com/arkfile/Arkfile/utils"
)

func isDebugMode() bool {
	return utils.IsDebugMode()
}

// decodeBase64IfNeeded attempts to detect and decode base64-encoded data.
// If the input is not valid base64, it returns the original data unchanged.
func decodeBase64IfNeeded(data []byte) ([]byte, error) {
	if len(data) > 60 && len(data)%4 == 0 {
		isBase64 := true
		for _, b := range data {
			if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
				(b >= '0' && b <= '9') || b == '+' || b == '/' || b == '=') {
				isBase64 = false
				break
			}
		}

		if isBase64 {
			decoded, err := base64.StdEncoding.DecodeString(string(data))
			if err == nil {
				return decoded, nil
			}
		}
	}

	return data, nil
}
