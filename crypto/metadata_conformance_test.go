package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type ownerMetadataFixture struct {
	FilenamePlaintext     string `json:"filename_plaintext"`
	FilenameNonceHex      string `json:"filename_nonce_hex"`
	FilenameCipherHex     string `json:"filename_ciphertext_and_tag_hex"`
	SHA256Plaintext       string `json:"sha256_plaintext"`
	SHA256NonceHex        string `json:"sha256_nonce_hex"`
	SHA256CipherHex       string `json:"sha256_ciphertext_and_tag_hex"`
	PasswordHintPlaintext string `json:"password_hint_plaintext"`
	PasswordHintNonceHex  string `json:"password_hint_nonce_hex"`
	PasswordHintCipherHex string `json:"password_hint_ciphertext_and_tag_hex"`
	TagsPlaintext         string `json:"tags_plaintext"`
	TagsNonceHex          string `json:"tags_nonce_hex"`
	TagsCipherHex         string `json:"tags_ciphertext_and_tag_hex"`
}

func TestMetadataFieldSharedFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/crypto-conformance-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		FileID        string `json:"file_id"`
		OwnerUsername string `json:"owner_username"`
		PasswordKDF   struct {
			AccountKeyHex string `json:"account_key_hex"`
		} `json:"password_kdf"`
		AAD struct {
			Filename     string `json:"encrypted_filename_hex"`
			SHA256       string `json:"encrypted_sha256sum_hex"`
			PasswordHint string `json:"encrypted_password_hint_hex"`
			Tags         string `json:"encrypted_tags_hex"`
		} `json:"aad"`
		OwnerMetadata ownerMetadataFixture `json:"owner_metadata"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(corpus.PasswordKDF.AccountKeyHex)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		field     string
		plaintext string
		nonceHex  string
		cipherHex string
		aadHex    string
	}{
		{"filename", AADFieldFilename, corpus.OwnerMetadata.FilenamePlaintext, corpus.OwnerMetadata.FilenameNonceHex, corpus.OwnerMetadata.FilenameCipherHex, corpus.AAD.Filename},
		{"sha256", AADFieldSha256, corpus.OwnerMetadata.SHA256Plaintext, corpus.OwnerMetadata.SHA256NonceHex, corpus.OwnerMetadata.SHA256CipherHex, corpus.AAD.SHA256},
		{"password_hint", AADFieldPasswordHint, corpus.OwnerMetadata.PasswordHintPlaintext, corpus.OwnerMetadata.PasswordHintNonceHex, corpus.OwnerMetadata.PasswordHintCipherHex, corpus.AAD.PasswordHint},
		{"tags", AADFieldTags, corpus.OwnerMetadata.TagsPlaintext, corpus.OwnerMetadata.TagsNonceHex, corpus.OwnerMetadata.TagsCipherHex, corpus.AAD.Tags},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nonce, err := hex.DecodeString(tc.nonceHex)
			if err != nil {
				t.Fatal(err)
			}
			wantCT, err := hex.DecodeString(tc.cipherHex)
			if err != nil {
				t.Fatal(err)
			}
			aad := BuildMetadataFieldAAD(corpus.FileID, tc.field, corpus.OwnerUsername)
			if hex.EncodeToString(aad) != tc.aadHex {
				t.Fatal("metadata AAD does not match shared fixture")
			}

			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			gotCT := gcm.Seal(nil, nonce, []byte(tc.plaintext), aad)
			if hex.EncodeToString(gotCT) != tc.cipherHex {
				t.Fatal("metadata ciphertext does not match shared fixture")
			}

			combined := append(append([]byte{}, nonce...), wantCT...)
			got, err := DecryptGCMWithAAD(combined, key, aad)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, []byte(tc.plaintext)) {
				t.Fatal("metadata plaintext does not match shared fixture")
			}
		})
	}
}
