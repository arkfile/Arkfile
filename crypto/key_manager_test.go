package crypto

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// ensureKeyManager returns the global KeyManager, initializing it with an
// in-memory SQLite database the first time. The crypto package has no TestMain,
// so the first test that needs a KeyManager bootstraps it here. Subsequent
// calls reuse the same instance (InitKeyManager is guarded by sync.Once).
func ensureKeyManager(t *testing.T) *KeyManager {
	t.Helper()
	if km, err := GetKeyManager(); err == nil {
		return km
	}

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open in-memory db: %v", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE system_keys (
			key_id TEXT PRIMARY KEY,
			key_type TEXT NOT NULL,
			encrypted_data BLOB NOT NULL,
			nonce BLOB NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP,
			consumed_at TIMESTAMP
		);
	`); err != nil {
		t.Fatalf("create system_keys: %v", err)
	}

	os.Setenv("ARKFILE_MASTER_KEY", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err := InitKeyManager(db); err != nil {
		t.Fatalf("init key manager: %v", err)
	}
	km, err := GetKeyManager()
	if err != nil {
		t.Fatalf("get key manager: %v", err)
	}
	return km
}

// TestListKeyIDs verifies prefix enumeration returns exactly the matching key
// ids (used by the JWT key-ring loader to discover versions) and an empty
// result for a non-matching prefix.
func TestListKeyIDs(t *testing.T) {
	km := ensureKeyManager(t)

	seed := make([]byte, 32)
	ids := []string{
		"listkeyidstest_alpha_v1",
		"listkeyidstest_alpha_v2",
		"listkeyidstest_alpha_v10",
		"listkeyidstest_beta_v1",
	}
	for _, id := range ids {
		if err := km.StoreKey(id, "jwt", seed); err != nil {
			t.Fatalf("store %s: %v", id, err)
		}
	}
	defer func() {
		for _, id := range ids {
			_ = km.DeleteKey(id)
		}
	}()

	got, err := km.ListKeyIDs("listkeyidstest_alpha_v")
	if err != nil {
		t.Fatalf("ListKeyIDs: %v", err)
	}
	want := map[string]bool{
		"listkeyidstest_alpha_v1":  true,
		"listkeyidstest_alpha_v2":  true,
		"listkeyidstest_alpha_v10": true,
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d ids, got %d: %v", len(want), len(got), got)
	}
	for _, id := range got {
		if !want[id] {
			t.Fatalf("unexpected id in result: %s (full: %v)", id, got)
		}
	}

	none, err := km.ListKeyIDs("listkeyidstest_nomatch_")
	if err != nil {
		t.Fatalf("ListKeyIDs(no match): %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("expected no matches, got %v", none)
	}
}

func TestStoreKeysAtomic_WritesBothRows(t *testing.T) {
	km := ensureKeyManager(t)

	priv := make([]byte, 32)
	seed := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i + 1)
		seed[i] = byte(i + 2)
	}

	if err := km.StoreKeysAtomic("opaque",
		SystemKeyMaterial{KeyID: "storeatomic_priv", RawKey: priv},
		SystemKeyMaterial{KeyID: "storeatomic_seed", RawKey: seed},
	); err != nil {
		t.Fatalf("StoreKeysAtomic: %v", err)
	}
	defer func() {
		_ = km.DeleteKey("storeatomic_priv")
		_ = km.DeleteKey("storeatomic_seed")
	}()

	gotPriv, err := km.GetKey("storeatomic_priv", "opaque")
	if err != nil {
		t.Fatalf("GetKey priv: %v", err)
	}
	if string(gotPriv) != string(priv) {
		t.Fatalf("priv mismatch")
	}

	gotSeed, err := km.GetKey("storeatomic_seed", "opaque")
	if err != nil {
		t.Fatalf("GetKey seed: %v", err)
	}
	if string(gotSeed) != string(seed) {
		t.Fatalf("seed mismatch")
	}
}

func TestStoreKeysAtomic_RejectsEmpty(t *testing.T) {
	km := ensureKeyManager(t)
	if err := km.StoreKeysAtomic("opaque"); err == nil {
		t.Fatal("expected error for empty key list")
	}
}
