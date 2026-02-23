package crypto

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

//go:embed chunking-params.json
var embeddedChunkingParams []byte

// ChunkingParams represents the unified chunking configuration
type ChunkingParams struct {
	PlaintextChunkSizeBytes int64          `json:"plaintextChunkSizeBytes"`
	Envelope                EnvelopeParams `json:"envelope"`
	AesGcm                  AesGcmParams   `json:"aesGcm"`
}

// EnvelopeParams represents envelope header configuration
type EnvelopeParams struct {
	Version         int            `json:"version"`
	HeaderSizeBytes int            `json:"headerSizeBytes"`
	KeyTypes        KeyTypeMapping `json:"keyTypes"`
}

// KeyTypeMapping maps password context names to envelope key type bytes
type KeyTypeMapping struct {
	Account int `json:"account"`
	Custom  int `json:"custom"`
}

// AesGcmParams represents AES-GCM configuration
type AesGcmParams struct {
	NonceSizeBytes int `json:"nonceSizeBytes"`
	TagSizeBytes   int `json:"tagSizeBytes"`
	KeySizeBytes   int `json:"keySizeBytes"`
}

var (
	chunkingParamsOnce  sync.Once
	chunkingParamsCache *ChunkingParams
	chunkingParamsErr   error
)

// GetChunkingParams returns the parsed chunking parameters from the embedded JSON
func GetChunkingParams() (*ChunkingParams, error) {
	chunkingParamsOnce.Do(func() {
		var params ChunkingParams
		if err := json.Unmarshal(embeddedChunkingParams, &params); err != nil {
			chunkingParamsErr = fmt.Errorf("failed to parse chunking-params.json: %w", err)
			return
		}
		chunkingParamsCache = &params
	})
	return chunkingParamsCache, chunkingParamsErr
}

// GetEmbeddedChunkingParamsJSON returns the raw embedded JSON for API serving
func GetEmbeddedChunkingParamsJSON() []byte {
	return embeddedChunkingParams
}

// MustGetChunkingParams returns the parsed chunking parameters or panics on error.
// Use this only during initialization where failure should be fatal.
func MustGetChunkingParams() *ChunkingParams {
	params, err := GetChunkingParams()
	if err != nil {
		panic(fmt.Sprintf("failed to load chunking params: %v", err))
	}
	return params
}

// PlaintextChunkSize returns the plaintext chunk size in bytes from the embedded config
func PlaintextChunkSize() int64 {
	return MustGetChunkingParams().PlaintextChunkSizeBytes
}

// AesGcmOverhead returns the per-chunk AES-GCM overhead (nonce + tag) in bytes
func AesGcmOverhead() int {
	p := MustGetChunkingParams()
	return p.AesGcm.NonceSizeBytes + p.AesGcm.TagSizeBytes
}

// EnvelopeHeaderSize returns the envelope header size in bytes (chunk 0 only)
func EnvelopeHeaderSize() int {
	return MustGetChunkingParams().Envelope.HeaderSizeBytes
}

// KeyTypeForContext returns the envelope key type byte for a given password context
func KeyTypeForContext(passwordType string) (byte, error) {
	p := MustGetChunkingParams()
	switch passwordType {
	case "account":
		return byte(p.Envelope.KeyTypes.Account), nil
	case "custom":
		return byte(p.Envelope.KeyTypes.Custom), nil
	default:
		return 0, fmt.Errorf("unknown password type: %s", passwordType)
	}
}
