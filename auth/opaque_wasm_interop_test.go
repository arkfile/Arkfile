package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type opaqueWASMRequest struct {
	Operation   string `json:"operation"`
	Password    string `json:"password,omitempty"`
	Username    string `json:"username,omitempty"`
	ServerID    string `json:"server_id,omitempty"`
	SecretHex   string `json:"secret_hex,omitempty"`
	ResponseB64 string `json:"response_b64,omitempty"`
}

type opaqueWASMResponse struct {
	RequestB64   string `json:"request_b64"`
	SecretHex    string `json:"secret_hex"`
	RecordB64    string `json:"record_b64"`
	AuthB64      string `json:"auth_b64"`
	ExportKeyHex string `json:"export_key_hex"`
}

func runOpaqueWASMStep(t *testing.T, bunPath, harnessPath, artifactPath string, request opaqueWASMRequest) opaqueWASMResponse {
	t.Helper()

	requestJSON, err := json.Marshal(request)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bunPath, harnessPath, artifactPath)
	cmd.Stdin = bytes.NewReader(requestJSON)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Run(), "WASM harness failed: %s", stderr.String())
	require.NoError(t, ctx.Err())

	var response opaqueWASMResponse
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &response), "invalid WASM harness output: %s", stdout.String())
	return response
}

func TestOpaqueNativeServerWASMClientInterop(t *testing.T) {
	bunPath, err := exec.LookPath("bun")
	if err != nil {
		t.Skip("bun is required for native/WASM OPAQUE interoperability testing")
	}

	_, currentFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	repoRoot := filepath.Dir(filepath.Dir(currentFile))
	harnessPath := filepath.Join(repoRoot, "scripts", "testing", "opaque-wasm-interop-harness.js")
	artifactPath := filepath.Join(repoRoot, "client", "static", "js", "libopaque.debug.js")
	if _, err := os.Stat(artifactPath); err != nil {
		t.Skip("built libopaque.debug.js is required for native/WASM OPAQUE interoperability testing")
	}

	ResetOpaqueServerKeysForTest()
	require.NoError(t, SetupServerKeys(nil))
	t.Cleanup(ResetOpaqueServerKeysForTest)

	const (
		username = "opaque-interop-user"
		password = "opaque interop password with sufficient entropy"
	)
	serverID := OpaqueServerID()

	registrationRequest := runOpaqueWASMStep(t, bunPath, harnessPath, artifactPath, opaqueWASMRequest{
		Operation: "registration_request",
		Password:  password,
	})
	requestBytes, err := base64.StdEncoding.DecodeString(registrationRequest.RequestB64)
	require.NoError(t, err)

	registrationResponse, registrationSecret, err := CreateRegistrationResponse(requestBytes)
	require.NoError(t, err)
	registrationFinal := runOpaqueWASMStep(t, bunPath, harnessPath, artifactPath, opaqueWASMRequest{
		Operation:   "registration_finalize",
		Username:    username,
		ServerID:    serverID,
		SecretHex:   registrationRequest.SecretHex,
		ResponseB64: base64.StdEncoding.EncodeToString(registrationResponse),
	})
	registrationRecord, err := base64.StdEncoding.DecodeString(registrationFinal.RecordB64)
	require.NoError(t, err)
	userRecord, err := StoreUserRecord(registrationSecret, registrationRecord)
	require.NoError(t, err)

	credentialRequest := runOpaqueWASMStep(t, bunPath, harnessPath, artifactPath, opaqueWASMRequest{
		Operation: "credential_request",
		Password:  password,
	})
	credentialRequestBytes, err := base64.StdEncoding.DecodeString(credentialRequest.RequestB64)
	require.NoError(t, err)
	credentialResponse, serverAuth, err := CreateCredentialResponse(credentialRequestBytes, userRecord, username)
	require.NoError(t, err)

	recovered := runOpaqueWASMStep(t, bunPath, harnessPath, artifactPath, opaqueWASMRequest{
		Operation:   "credential_recover",
		Username:    username,
		ServerID:    serverID,
		SecretHex:   credentialRequest.SecretHex,
		ResponseB64: base64.StdEncoding.EncodeToString(credentialResponse),
	})
	clientAuth, err := base64.StdEncoding.DecodeString(recovered.AuthB64)
	require.NoError(t, err)
	require.NoError(t, UserAuth(serverAuth, clientAuth))

	registrationExportKey, err := hex.DecodeString(registrationFinal.ExportKeyHex)
	require.NoError(t, err)
	loginExportKey, err := hex.DecodeString(recovered.ExportKeyHex)
	require.NoError(t, err)
	require.Equal(t, registrationExportKey, loginExportKey)
}
