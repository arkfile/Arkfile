package storage

import (
	"crypto/rand"
	"fmt"
	"io"
)

// paddingReader generates padding bytes on demand
type paddingReader struct {
	size int64
	read int64
}

func (r *paddingReader) Read(p []byte) (n int, err error) {
	if r.read >= r.size {
		return 0, io.EOF
	}

	toRead := int64(len(p))
	if toRead > r.size-r.read {
		toRead = r.size - r.read
	}

	// Generate random padding bytes
	n = int(toRead)
	if _, err := rand.Read(p[:n]); err != nil {
		return 0, fmt.Errorf("failed to generate padding: %w", err)
	}

	r.read += toRead
	return n, nil
}

// limitedReadCloser wraps a ReadCloser and limits reading to a specific size
type limitedReadCloser struct {
	io.ReadCloser
	limit int64
	read  int64
}

func (l *limitedReadCloser) Read(p []byte) (n int, err error) {
	if l.read >= l.limit {
		return 0, io.EOF
	}

	toRead := int64(len(p))
	if toRead > l.limit-l.read {
		toRead = l.limit - l.read
	}

	n, err = l.ReadCloser.Read(p[:toRead])
	l.read += int64(n)

	if l.read >= l.limit && err == nil {
		err = io.EOF
	}

	return n, err
}
