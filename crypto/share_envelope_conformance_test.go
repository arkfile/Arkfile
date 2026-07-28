package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type shareEnvelopeConformanceFixture struct {
	Password                string `json:"password"`
	SaltBase64              string `json:"salt_base64"`
	DerivedKeyHex           string `json:"derived_key_hex"`
	ShareID                 string `json:"share_id"`
	FileID                  string `json:"file_id"`
	FEKHex                  string `json:"fek_hex"`
	DownloadTokenBase64     string `json:"download_token_base64"`
	Filename                string `json:"filename"`
	SizeBytes               int64  `json:"size_bytes"`
	SHA256                  string `json:"sha256"`
	AADHex                  string `json:"aad_hex"`
	NonceHex                string `json:"nonce_hex"`
	PlaintextJSON           string `json:"plaintext_json"`
	EncryptedEnvelopeBase64 string `json:"encrypted_envelope_base64"`
	WeakKDFEncryptedBase64  string `json:"weak_kdf_encrypted_envelope_base64"`
}

func loadShareEnvelopeConformanceFixture(t *testing.T) shareEnvelopeConformanceFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/crypto-conformance-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		CorpusVersion int                             `json:"corpus_version"`
		ShareEnvelope shareEnvelopeConformanceFixture `json:"share_envelope"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.CorpusVersion != 2 {
		t.Fatalf("unsupported crypto conformance corpus version: %d", corpus.CorpusVersion)
	}
	return corpus.ShareEnvelope
}

func decodeFixtureBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func decodeFixtureHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestShareEnvelopeSharedFixtureDecrypt(t *testing.T) {
	fixture := loadShareEnvelopeConformanceFixture(t)
	key, err := DeriveShareKey(fixture.Password, fixture.SaltBase64)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key) != fixture.DerivedKeyHex {
		t.Fatal("share key does not match shared fixture")
	}

	aad := CreateAAD(fixture.ShareID, fixture.FileID)
	if hex.EncodeToString(aad) != fixture.AADHex {
		t.Fatal("share envelope AAD does not match shared fixture")
	}
	encrypted := decodeFixtureBase64(t, fixture.EncryptedEnvelopeBase64)
	nonce := decodeFixtureHex(t, fixture.NonceHex)
	if !bytes.HasPrefix(encrypted, nonce) {
		t.Fatal("share envelope nonce does not match shared fixture")
	}

	plaintext, err := DecryptGCMWithAAD(encrypted, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != fixture.PlaintextJSON {
		t.Fatal("share envelope plaintext does not match shared fixture")
	}
	envelope, err := ParseShareEnvelope(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(decodeFixtureBase64(t, envelope.FEK)) != fixture.FEKHex {
		t.Fatal("share envelope FEK does not match shared fixture")
	}
	if envelope.DownloadToken != fixture.DownloadTokenBase64 ||
		envelope.Filename != fixture.Filename ||
		envelope.SizeBytes != fixture.SizeBytes ||
		envelope.SHA256 != fixture.SHA256 {
		t.Fatal("share envelope metadata does not match shared fixture")
	}
}

func TestShareEnvelopeSharedFixtureRejectsTampering(t *testing.T) {
	fixture := loadShareEnvelopeConformanceFixture(t)
	key, err := DeriveShareKey(fixture.Password, fixture.SaltBase64)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := decodeFixtureBase64(t, fixture.EncryptedEnvelopeBase64)

	t.Run("wrong share ID", func(t *testing.T) {
		if _, err := DecryptGCMWithAAD(encrypted, key, CreateAAD("wrong-share", fixture.FileID)); err == nil {
			t.Fatal("share envelope decrypted with wrong share ID")
		}
	})
	t.Run("wrong file ID", func(t *testing.T) {
		if _, err := DecryptGCMWithAAD(encrypted, key, CreateAAD(fixture.ShareID, "wrong-file")); err == nil {
			t.Fatal("share envelope decrypted with wrong file ID")
		}
	})
	t.Run("ciphertext corruption", func(t *testing.T) {
		corrupted := append([]byte(nil), encrypted...)
		corrupted[len(corrupted)-1] ^= 0x01
		if _, err := DecryptGCMWithAAD(corrupted, key, CreateAAD(fixture.ShareID, fixture.FileID)); err == nil {
			t.Fatal("corrupted share envelope decrypted")
		}
	})
	t.Run("sub-floor KDF parameters", func(t *testing.T) {
		weak := decodeFixtureBase64(t, fixture.WeakKDFEncryptedBase64)
		plaintext, err := DecryptGCMWithAAD(weak, key, CreateAAD(fixture.ShareID, fixture.FileID))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseShareEnvelope(plaintext); err == nil {
			t.Fatal("share envelope accepted sub-floor KDF parameters")
		}
	})
}
