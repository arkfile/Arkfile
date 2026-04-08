package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
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

// StreamingHashTeeReader wraps an io.Reader to calculate hash while reading
type StreamingHashTeeReader struct {
	reader       io.Reader
	hash         hash.Hash
	expectedHash string
	bytesRead    int64
}

// NewStreamingHashTeeReader creates a new tee reader that calculates hash while reading
func NewStreamingHashTeeReader(reader io.Reader, expectedHash string) *StreamingHashTeeReader {
	return &StreamingHashTeeReader{
		reader:       reader,
		hash:         sha256.New(),
		expectedHash: expectedHash,
	}
}

// Read implements io.Reader interface, calculating hash as data is read
func (r *StreamingHashTeeReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if n > 0 {
		r.hash.Write(p[:n])
		r.bytesRead += int64(n)
	}
	return n, err
}

// VerifyHash checks if the calculated hash matches the expected hash
func (r *StreamingHashTeeReader) VerifyHash() (bool, string) {
	calculatedHash := hex.EncodeToString(r.hash.Sum(nil))
	return calculatedHash == r.expectedHash, calculatedHash
}

// GetBytesRead returns the total number of bytes read
func (r *StreamingHashTeeReader) GetBytesRead() int64 {
	return r.bytesRead
}
