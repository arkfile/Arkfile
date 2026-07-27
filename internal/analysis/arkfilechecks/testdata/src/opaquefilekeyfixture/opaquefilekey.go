package opaquefilekeyfixture

import (
	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/crypto"
)

func rejected(secret, response, salt, fek []byte) {
	sessionKey, _, exportKey, _ := auth.ClientRecoverCredentials(secret, response, "user", "server")
	_, _ = crypto.DeriveAccountPasswordKey(sessionKey, salt) // want "OPAQUE session or export material"

	copiedExport := exportKey
	_, _ = crypto.EncryptFEK(fek, copiedExport, salt, "file", "account") // want "OPAQUE session or export material"

	values := struct {
		OPAQUEExport []byte
	}{OPAQUEExport: exportKey}
	_, _ = crypto.DeriveAccountPasswordKey(values.OPAQUEExport, salt) // want "OPAQUE session or export material"
}

func rejectedRegistration(context, response, salt []byte) {
	_, exportKey, _ := auth.ClientFinalizeRegistration(context, response, "user", "server")
	_, _ = crypto.DeriveAccountPasswordKey(exportKey, salt) // want "OPAQUE session or export material"
}

func accepted(password, salt []byte) {
	_, _ = crypto.DeriveAccountPasswordKey(password, salt)
}
