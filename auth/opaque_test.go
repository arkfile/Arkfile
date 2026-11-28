package auth

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/arkfile/Arkfile/config"
)

// TestOpaqueServerID verifies the single source of truth for the OPAQUE server
// identity (idS). All OPAQUE participants (server, browser, CLI) must agree on
// this value, so the default and configured-override behavior are guarded here.
func TestOpaqueServerID(t *testing.T) {
	// Minimal storage env so config.LoadConfig() passes validation, since
	// OpaqueServerID() loads config to read Server.Domain.
	baseEnv := map[string]string{
		"STORAGE_PROVIDER_1":   "generic-s3",
		"STORAGE_1_ENDPOINT":   "http://localhost:9332",
		"STORAGE_1_ACCESS_KEY": "test",
		"STORAGE_1_SECRET_KEY": "test",
		"STORAGE_1_BUCKET":     "test",
	}

	cases := []struct {
		name        string
		domainValue string // "" means unset
		want        string
	}{
		{name: "unset falls back to default", domainValue: "", want: DefaultOpaqueServerID},
		{name: "configured FQDN is used", domainValue: "test.arkfile.net", want: "test.arkfile.net"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config.ResetConfigForTest()

			keys := []string{"ARKFILE_DOMAIN"}
			for k := range baseEnv {
				keys = append(keys, k)
			}
			originalEnv := make(map[string]string)
			for _, k := range keys {
				originalEnv[k] = os.Getenv(k)
			}
			defer func() {
				for _, k := range keys {
					if originalEnv[k] == "" {
						os.Unsetenv(k)
					} else {
						os.Setenv(k, originalEnv[k])
					}
				}
				config.ResetConfigForTest()
			}()

			for k, v := range baseEnv {
				os.Setenv(k, v)
			}
			if tc.domainValue == "" {
				os.Unsetenv("ARKFILE_DOMAIN")
			} else {
				os.Setenv("ARKFILE_DOMAIN", tc.domainValue)
			}

			assert.Equal(t, tc.want, OpaqueServerID())
		})
	}
}

func TestSodiumInitializedAtPackageInit(t *testing.T) {
	// sodium_init returns 1 when already initialized by auth.init(), never -1.
	assert.Equal(t, 1, sodiumInitStatus())
}

func TestOpaqueClientRoundTripAndExportKeyLength(t *testing.T) {
	ResetOpaqueServerKeysForTest()
	require.NoError(t, SetupServerKeys(nil))
	t.Cleanup(ResetOpaqueServerKeysForTest)

	const username = "opaque.client.user"
	serverID := OpaqueServerID()
	password := []byte("CorrectHorseBatteryStaple-2026!")

	usrCtx, regReq, err := ClientCreateRegistrationRequest(password)
	require.NoError(t, err)
	regResp, regSec, err := CreateRegistrationResponse(regReq)
	require.NoError(t, err)
	regRec, regExportKey, err := ClientFinalizeRegistration(usrCtx, regResp, username, serverID)
	require.NoError(t, err)
	require.Len(t, regExportKey, OPAQUE_EXPORT_KEY_LEN)

	userRecord, err := StoreUserRecord(regSec, regRec)
	require.NoError(t, err)

	// Successful login recovers the full 64-byte export key matching registration.
	clientSec, credReq, err := ClientCreateCredentialRequest(password)
	require.NoError(t, err)
	credResp, serverAuth, err := CreateCredentialResponse(credReq, userRecord, username)
	require.NoError(t, err)
	sk, clientAuth, loginExportKey, err := ClientRecoverCredentials(clientSec, credResp, username, serverID)
	require.NoError(t, err)
	require.Len(t, sk, OPAQUE_SHARED_SECRETBYTES)
	require.Len(t, clientAuth, OPAQUE_AUTH_U_LEN)
	require.Len(t, loginExportKey, OPAQUE_EXPORT_KEY_LEN)
	assert.Equal(t, regExportKey, loginExportKey)
	require.NoError(t, UserAuth(serverAuth, clientAuth))

	// Wrong password fails cleanly without corrupting heap across repeated attempts.
	wrongPassword := []byte("WrongPasswordForHeapCheck-2026!")
	for i := 0; i < 32; i++ {
		badSec, badReq, err := ClientCreateCredentialRequest(wrongPassword)
		require.NoError(t, err)
		badResp, _, err := CreateCredentialResponse(badReq, userRecord, username)
		require.NoError(t, err)
		_, _, _, err = ClientRecoverCredentials(badSec, badResp, username, serverID)
		require.Error(t, err)
	}
}
