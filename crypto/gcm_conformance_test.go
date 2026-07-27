package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAESGCMSharedFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/crypto-conformance-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		AESGCM struct {
			Key        string `json:"key_hex"`
			Nonce      string `json:"nonce_hex"`
			Plaintext  string `json:"plaintext_hex"`
			AAD        string `json:"aad_hex"`
			Ciphertext string `json:"ciphertext_and_tag_hex"`
		} `json:"aes_gcm"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	decode := func(value string) []byte {
		out, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	key := decode(fixture.AESGCM.Key)
	nonce := decode(fixture.AESGCM.Nonce)
	plaintext := decode(fixture.AESGCM.Plaintext)
	aad := decode(fixture.AESGCM.AAD)
	expected := decode(fixture.AESGCM.Ciphertext)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	if got := gcm.Seal(nil, nonce, plaintext, aad); hex.EncodeToString(got) != hex.EncodeToString(expected) {
		t.Fatal("AES-GCM ciphertext does not match shared fixture")
	}
	decrypted, err := gcm.Open(nil, nonce, expected, aad)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(decrypted) != fixture.AESGCM.Plaintext {
		t.Fatal("AES-GCM plaintext does not match shared fixture")
	}
}
