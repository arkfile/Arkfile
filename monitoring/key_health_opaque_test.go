package monitoring

import (
	"database/sql"
	"testing"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/crypto"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupOpaqueHealthTest(t *testing.T) *KeyHealthMonitor {
	t.Helper()
	config.ResetConfigForTest()

	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`
		CREATE TABLE system_keys (
			key_id TEXT PRIMARY KEY,
			key_type TEXT NOT NULL,
			encrypted_data BLOB NOT NULL,
			nonce BLOB NOT NULL
		);
	`)
	require.NoError(t, err)

	t.Setenv("ARKFILE_MASTER_KEY", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, crypto.InitKeyManager(db))

	return NewKeyHealthMonitor(db, config.MonitoringConfig{})
}

func TestCheckOpaqueServerKeys_HealthyWhenBothKeysPresent(t *testing.T) {
	khm := setupOpaqueHealthTest(t)
	require.NoError(t, auth.SetupServerKeys(nil))

	component := &KeyComponent{
		Type:    "opaque_server",
		Path:    auth.OpaqueServerPrivateKeyID,
		Details: make(map[string]interface{}),
	}
	khm.checkOpaqueServerKeys(component)

	assert.Equal(t, HealthStatusHealthy, component.Status)
	assert.Equal(t, auth.OpaqueServerPrivateKeyID, component.Details["private_key_id"])
	assert.Equal(t, auth.OpaqueOPRFSeedKeyID, component.Details["oprf_seed_key_id"])
}

func TestCheckOpaqueServerKeys_CriticalWhenKeysMissing(t *testing.T) {
	khm := setupOpaqueHealthTest(t)

	component := &KeyComponent{
		Type:    "opaque_server",
		Path:    auth.OpaqueServerPrivateKeyID,
		Details: make(map[string]interface{}),
	}
	khm.checkOpaqueServerKeys(component)

	assert.Equal(t, HealthStatusCritical, component.Status)
	assert.Contains(t, component.ErrorMessage, "private key")
}
