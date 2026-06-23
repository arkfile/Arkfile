package crypto

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestDeriveUserSecretSubkeyFromMaster_DomainSeparation(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i)
	}

	mfaSub, err := DeriveUserSecretSubkeyFromMaster(master, []byte("mfa_user"))
	if err != nil {
		t.Fatal(err)
	}
	contactSub, err := DeriveUserSecretSubkeyFromMaster(master, []byte("contact_info"))
	if err != nil {
		t.Fatal(err)
	}
	if string(mfaSub) == string(contactSub) {
		t.Fatal("mfa_user and contact_info subkeys must differ")
	}
}

func TestReencryptMFACredentialData_RoundTrip(t *testing.T) {
	oldMaster := make([]byte, 32)
	newMaster := make([]byte, 32)
	for i := range oldMaster {
		oldMaster[i] = byte(i + 1)
	}
	for i := range newMaster {
		newMaster[i] = byte(255 - i)
	}

	username := "alice"
	secret := "JBSWY3DPEHPK3PXP"

	oldKey, err := DeriveMFAUserKeyFromMaster(oldMaster, username)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := EncryptGCM([]byte(secret), oldKey)
	if err != nil {
		t.Fatal(err)
	}

	reencrypted, err := ReencryptMFACredentialData(oldMaster, newMaster, username, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	newKey, err := DeriveMFAUserKeyFromMaster(newMaster, username)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := DecryptGCM(reencrypted, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != secret {
		t.Fatalf("expected %q, got %q", secret, string(plaintext))
	}
}

func TestReencryptMFACredentialData_WebAuthnFixture(t *testing.T) {
	oldMaster := make([]byte, 32)
	newMaster := make([]byte, 32)
	copy(oldMaster, []byte("old-user-secret-master-material"))
	copy(newMaster, []byte("new-user-secret-master-material"))

	username := "webauthn-user"
	payload := map[string]interface{}{
		"credential_id": "cred-123",
		"public_key":    "cose-key-bytes",
		"sign_count":    42,
	}
	raw, _ := json.Marshal(payload)

	oldKey, err := DeriveMFAUserKeyFromMaster(oldMaster, username)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := EncryptGCM(raw, oldKey)
	if err != nil {
		t.Fatal(err)
	}

	reencrypted, err := ReencryptMFACredentialData(oldMaster, newMaster, username, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	newKey, err := DeriveMFAUserKeyFromMaster(newMaster, username)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := DecryptGCM(reencrypted, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != string(raw) {
		t.Fatal("webauthn fixture plaintext mismatch after rotation")
	}
}

func TestReencryptContactInfo_RoundTrip(t *testing.T) {
	oldMaster := make([]byte, 32)
	newMaster := make([]byte, 32)
	for i := range oldMaster {
		oldMaster[i] = byte(i + 10)
	}
	for i := range newMaster {
		newMaster[i] = byte(i + 20)
	}

	plaintext := []byte(`{"display_name":"Alice","contacts":[],"notes":""}`)
	oldKey, err := DeriveUserSecretSubkeyFromMaster(oldMaster, []byte("contact_info"))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := EncryptGCM(plaintext, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	nonceSize := AesGcmNonceSize()
	dataB64 := base64.StdEncoding.EncodeToString(encrypted[nonceSize:])
	nonceB64 := base64.StdEncoding.EncodeToString(encrypted[:nonceSize])

	newData, newNonce, err := ReencryptContactInfo(oldMaster, newMaster, dataB64, nonceB64)
	if err != nil {
		t.Fatal(err)
	}

	newKey, err := DeriveUserSecretSubkeyFromMaster(newMaster, []byte("contact_info"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, _ := base64.StdEncoding.DecodeString(newData)
	nonce, _ := base64.StdEncoding.DecodeString(newNonce)
	out, err := DecryptGCM(append(nonce, ciphertext...), newKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(plaintext) {
		t.Fatalf("expected %s, got %s", plaintext, out)
	}
}

func TestReencryptAllUserSecretWrappedRows(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	schema := `
		CREATE TABLE user_mfa_credentials (
			credential_id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			method_type TEXT NOT NULL DEFAULT 'totp',
			credential_data BLOB NOT NULL
		);
		CREATE TABLE user_contact_info (
			username TEXT PRIMARY KEY,
			encrypted_data BLOB NOT NULL,
			nonce TEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}

	oldMaster := make([]byte, 32)
	newMaster := make([]byte, 32)
	copy(oldMaster, []byte("old-user-secret-master-material"))
	copy(newMaster, []byte("new-user-secret-master-material"))

	username := "bob"
	oldKey, _ := DeriveMFAUserKeyFromMaster(oldMaster, username)
	encMFA, _ := EncryptGCM([]byte("SECRET123"), oldKey)
	if _, err := db.Exec(`INSERT INTO user_mfa_credentials (credential_id, username, method_type, credential_data) VALUES (?, ?, 'totp', ?)`, "cred-1", username, encMFA); err != nil {
		t.Fatal(err)
	}

	contactKey, _ := DeriveUserSecretSubkeyFromMaster(oldMaster, []byte("contact_info"))
	encContact, _ := EncryptGCM([]byte(`{"display_name":"Bob","contacts":[],"notes":""}`), contactKey)
	nonceSize := AesGcmNonceSize()
	if _, err := db.Exec(
		`INSERT INTO user_contact_info (username, encrypted_data, nonce) VALUES (?, ?, ?)`,
		username,
		base64.StdEncoding.EncodeToString(encContact[nonceSize:]),
		base64.StdEncoding.EncodeToString(encContact[:nonceSize]),
	); err != nil {
		t.Fatal(err)
	}

	stats, err := ReencryptAllUserSecretWrappedRows(db, oldMaster, newMaster)
	if err != nil {
		t.Fatal(err)
	}
	if stats.MFACredentials != 1 || stats.ContactInfo != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	newMFAKey, _ := DeriveMFAUserKeyFromMaster(newMaster, username)
	var storedMFA []byte
	if err := db.QueryRow(`SELECT credential_data FROM user_mfa_credentials WHERE username = ?`, username).Scan(&storedMFA); err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptGCM(storedMFA, newMFAKey)
	if err != nil || string(pt) != "SECRET123" {
		t.Fatalf("MFA decrypt after DB rotation failed: %v %q", err, pt)
	}
}
