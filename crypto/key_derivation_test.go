package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type cryptoConformanceKDF struct {
	PublicSaltHex string `json:"public_salt_hex"`
	PasswordKDF   struct {
		Password      string `json:"password"`
		AccountKeyHex string `json:"account_key_hex"`
		CustomKeyHex  string `json:"custom_key_hex"`
	} `json:"password_kdf"`
}

func loadKDFConformance(t *testing.T) cryptoConformanceKDF {
	t.Helper()
	raw, err := os.ReadFile("testdata/crypto-conformance-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture cryptoConformanceKDF
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestPasswordKDFConformance(t *testing.T) {
	fixture := loadKDFConformance(t)
	salt, err := hex.DecodeString(fixture.PublicSaltHex)
	if err != nil {
		t.Fatal(err)
	}

	accountKey, err := DeriveAccountPasswordKey([]byte(fixture.PasswordKDF.Password), salt)
	if err != nil {
		t.Fatal(err)
	}
	customKey, err := DeriveCustomPasswordKey([]byte(fixture.PasswordKDF.Password), salt)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(accountKey) != fixture.PasswordKDF.AccountKeyHex {
		t.Fatalf("account key does not match pinned fixture")
	}
	if hex.EncodeToString(customKey) != fixture.PasswordKDF.CustomKeyHex {
		t.Fatalf("custom key does not match pinned fixture")
	}
	if bytes.Equal(accountKey, customKey) {
		t.Fatal("account and custom KDF contexts must be separated")
	}
}

func TestGeneratePasswordSalt(t *testing.T) {
	first, err := GeneratePasswordSalt()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GeneratePasswordSalt()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePasswordSalt(first); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("separate salt generations must not reuse bytes")
	}
}

func TestValidatePasswordSaltRejectsWrongLengths(t *testing.T) {
	for _, size := range []int{0, OwnerEnvelopeSaltSize() - 1, OwnerEnvelopeSaltSize() + 1} {
		if err := ValidatePasswordSalt(make([]byte, size)); err == nil {
			t.Fatalf("accepted salt length %d", size)
		}
	}
}

func TestDerivePasswordKeyRejectsUnknownContext(t *testing.T) {
	_, err := DerivePasswordKey([]byte("ValidPassword-2026!"), make([]byte, OwnerEnvelopeSaltSize()), "opaque")
	if err == nil {
		t.Fatal("accepted unsupported password context")
	}
}

func TestDeriveArgon2IDKeyInputValidation(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, OwnerEnvelopeSaltSize())
	if _, err := DeriveArgon2IDKey(nil, salt, 32, 65536, 3, 1); err == nil {
		t.Fatal("accepted empty password")
	}
	if _, err := DeriveArgon2IDKey([]byte("password"), nil, 32, 65536, 3, 1); err == nil {
		t.Fatal("accepted empty salt")
	}
	if _, err := DeriveArgon2IDKey([]byte("password"), salt, 0, 65536, 3, 1); err == nil {
		t.Fatal("accepted zero key length")
	}
	tooLong := bytes.Repeat([]byte{'a'}, MaxPasswordBytes+1)
	if _, err := DeriveArgon2IDKey(tooLong, salt, 32, 65536, 3, 1); err == nil {
		t.Fatal("accepted oversized password")
	}
}

func TestDifferentPublicSaltsProduceDifferentKeys(t *testing.T) {
	password := []byte("ValidPassword-2026!")
	firstSalt := bytes.Repeat([]byte{1}, OwnerEnvelopeSaltSize())
	secondSalt := bytes.Repeat([]byte{2}, OwnerEnvelopeSaltSize())
	first, err := DeriveAccountPasswordKey(password, firstSalt)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DeriveAccountPasswordKey(password, secondSalt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("different public salts produced the same Account Key")
	}
}

func TestDerivedPasswordKeyWorksWithGCM(t *testing.T) {
	salt := bytes.Repeat([]byte{3}, OwnerEnvelopeSaltSize())
	key, err := DeriveAccountPasswordKey([]byte("ValidPassword-2026!"), salt)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("derived-key encryption")
	ciphertext, err := EncryptGCM(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptGCM(ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("derived key round trip mismatch")
	}
}

func TestEmbeddedArgon2Parameters(t *testing.T) {
	var parsed map[string]interface{}
	if err := json.Unmarshal(GetEmbeddedArgon2ParamsJSON(), &parsed); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"memoryCostKiB", "timeCost", "parallelism", "keyLength", "variant"} {
		if _, ok := parsed[field]; !ok {
			t.Fatalf("missing Argon2 parameter %s", field)
		}
	}
	if parsed["variant"] != "Argon2id" {
		t.Fatalf("unexpected Argon2 variant %v", parsed["variant"])
	}
}
