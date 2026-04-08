package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// PaddingCalculator handles file padding calculations for privacy
type PaddingCalculator struct{}

// NewPaddingCalculator creates a new padding calculator instance
func NewPaddingCalculator() *PaddingCalculator {
	return &PaddingCalculator{}
}

// CalculatePaddedSize returns the padded size for a given file size using
// percentage-based block alignment with randomized jitter.
//
// Block size = 2% of file size (minimum 64KB). The file is rounded up to
// the nearest block boundary, then random jitter (0 to 10% of block size)
// is added. This gives a consistent worst-case padding overhead of ~2.2%
// for files above 3.2MB, with the 64KB minimum floor providing size
// obfuscation for smaller files at negligible absolute cost.
func (p *PaddingCalculator) CalculatePaddedSize(originalSize int64) (int64, error) {
	// Block size = 2% of file size, minimum 64KB
	blockSize := originalSize / 50
	const minBlockSize int64 = 64 * 1024
	if blockSize < minBlockSize {
		blockSize = minBlockSize
	}

	// Cryptographically random jitter: 0 to 10% of block size
	maxJitter := blockSize / 10
	if maxJitter <= 0 {
		maxJitter = 1
	}
	jitter, err := rand.Int(rand.Reader, big.NewInt(maxJitter))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random padding jitter: %w", err)
	}

	// Round up to nearest block boundary and add jitter
	padded := ((originalSize + blockSize - 1) / blockSize) * blockSize
	return padded + jitter.Int64(), nil
}

// GeneratePaddingBytes generates cryptographically secure random padding bytes
func (p *PaddingCalculator) GeneratePaddingBytes(size int64) ([]byte, error) {
	if size <= 0 {
		return []byte{}, nil
	}

	padding := make([]byte, size)
	_, err := rand.Read(padding)
	if err != nil {
		return nil, fmt.Errorf("failed to generate padding bytes: %w", err)
	}
	return padding, nil
}

// GetPaddingSize calculates how much padding is needed given original and target sizes
func (p *PaddingCalculator) GetPaddingSize(originalSize, targetSize int64) int64 {
	if targetSize <= originalSize {
		return 0
	}
	return targetSize - originalSize
}
