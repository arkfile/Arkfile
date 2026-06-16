package auth

import (
	"fmt"
	"strings"
	"sync"

	"github.com/84adam/Arkfile/config"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/go-webauthn/webauthn/protocol"
)

var (
	webAuthnOnce sync.Once
	webAuthnInst *webauthn.WebAuthn
	webAuthnErr  error
)

// GetWebAuthn returns the shared WebAuthn relying-party instance.
func GetWebAuthn() (*webauthn.WebAuthn, error) {
	webAuthnOnce.Do(func() {
		cfg := config.GetConfig()
		rpID := strings.TrimSpace(cfg.Server.Domain)
		if rpID == "" {
			rpID = "localhost"
		}

		origins := make([]string, 0, 2)
		if base := strings.TrimSpace(cfg.Server.BaseURL); base != "" {
			origins = append(origins, strings.TrimRight(base, "/"))
		}
		for _, o := range cfg.Server.AllowedOrigins {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				origins = append(origins, strings.TrimRight(trimmed, "/"))
			}
		}
		if len(origins) == 0 {
			if rpID == "localhost" {
				origins = append(origins, "https://localhost:8443")
			} else {
				origins = append(origins, "https://"+rpID)
			}
		}

		notRequired := false
		webAuthnInst, webAuthnErr = webauthn.New(&webauthn.Config{
			RPID:                 rpID,
			RPDisplayName:        "Arkfile",
			RPOrigins:            origins,
			EncodeUserIDAsString: true,
			AttestationPreference: protocol.PreferNoAttestation,
			AuthenticatorSelection: protocol.AuthenticatorSelection{
				AuthenticatorAttachment: protocol.CrossPlatform,
				RequireResidentKey:      &notRequired,
				ResidentKey:             protocol.ResidentKeyRequirementDiscouraged,
				UserVerification:        protocol.VerificationPreferred,
			},
		})
		if webAuthnErr != nil {
			webAuthnErr = fmt.Errorf("webauthn config: %w", webAuthnErr)
		}
	})

	return webAuthnInst, webAuthnErr
}
