package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
)

// StreamingHashState manages the running hash calculation during chunked uploads
type StreamingHashState struct {
	hash       hash.Hash
	sessionID  string
	totalBytes int64
}

// NewStreamingHashState creates a new streaming hash state for an upload session
func NewStreamingHashState(sessionID string) *StreamingHashState {
	return &StreamingHashState{
		hash:      sha256.New(),
		sessionID: sessionID,
	}
}

// WriteChunk adds a chunk to the running hash and returns the data unchanged
func (s *StreamingHashState) WriteChunk(data []byte) ([]byte, error) {
	// Write chunk data to the hash
	n, err := s.hash.Write(data)
	if err != nil {
		return nil, err
	}

	s.totalBytes += int64(n)
	return data, nil
}

// FinalizeHash completes the hash calculation and returns the final SHA256 hex string
func (s *StreamingHashState) FinalizeHash() string {
	return hex.EncodeToString(s.hash.Sum(nil))
}
