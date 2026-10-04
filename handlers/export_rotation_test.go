package handlers

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/arkfile/Arkfile/crypto"
	"github.com/arkfile/Arkfile/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildBundleMetadataIncludesAccountKDFMetadata(t *testing.T) {
	file := &models.File{
		FileID:         "00112233-4455-6677-8899-aabbccddeeff",
		OwnerUsername:  "export-owner",
		PasswordType:   "account",
		EncryptedFEK:   "encrypted-fek",
		SizeBytes:      1024,
		PaddedSize:     sql.NullInt64{Int64: 2048, Valid: true},
		ChunkCount:     1,
		ChunkSizeBytes: int64(crypto.PlaintextChunkSize()),
	}
	salt := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	metadata := buildBundleMetadata(file, salt, int(crypto.OwnerEnvelopeKDFProfile()))
	assert.Equal(t, 2, metadata.Version)
	assert.Equal(t, salt, metadata.AccountKDFSalt)
	assert.Equal(t, int(crypto.OwnerEnvelopeKDFProfile()), metadata.AccountKDFProfile)
	assert.Equal(t, int(crypto.OwnerEnvelopeVersion()), metadata.EnvelopeVersion)
	assert.Equal(t, file.OwnerUsername, metadata.OwnerUsername)
}

func TestBuildBundleMetadataCopiesEncryptedPasswordHint(t *testing.T) {
	const hintCiphertext = "aGludC1jaXBoZXJ0ZXh0LWJ5dGVz"
	const hintNonce = "bm9uY2UtYnl0ZXM="
	file := &models.File{
		FileID:                "00112233-4455-6677-8899-aabbccddeeff",
		OwnerUsername:         "export-owner",
		PasswordType:          "custom",
		EncryptedFEK:          "encrypted-fek",
		SizeBytes:             1024,
		ChunkCount:            1,
		EncryptedPasswordHint: hintCiphertext,
		PasswordHintNonce:     hintNonce,
	}
	salt := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	metadata := buildBundleMetadata(file, salt, int(crypto.OwnerEnvelopeKDFProfile()))
	assert.Equal(t, hintCiphertext, metadata.EncryptedPasswordHint)
	assert.Equal(t, hintNonce, metadata.PasswordHintNonce)
	assert.Equal(t, salt, metadata.AccountKDFSalt)

	encoded, err := json.Marshal(metadata)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"encrypted_password_hint":"`+hintCiphertext+`"`)
	assert.Contains(t, string(encoded), `"password_hint_nonce":"`+hintNonce+`"`)
}

func TestBuildBundleMetadataOmitsIncompletePasswordHint(t *testing.T) {
	salt := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	cases := []struct {
		name       string
		ciphertext string
		nonce      string
	}{
		{"no hint", "", ""},
		{"ciphertext only", "aGludA==", ""},
		{"nonce only", "", "bm9uY2U="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file := &models.File{
				FileID:                "00112233-4455-6677-8899-aabbccddeeff",
				OwnerUsername:         "export-owner",
				PasswordType:          "custom",
				EncryptedPasswordHint: tc.ciphertext,
				PasswordHintNonce:     tc.nonce,
			}
			metadata := buildBundleMetadata(file, salt, int(crypto.OwnerEnvelopeKDFProfile()))
			assert.Empty(t, metadata.EncryptedPasswordHint)
			assert.Empty(t, metadata.PasswordHintNonce)
			encoded, err := json.Marshal(metadata)
			require.NoError(t, err)
			assert.False(t, strings.Contains(string(encoded), "password_hint"))
		})
	}
}
