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

// CalculatePaddedSize returns the padded size for a given file size using tiered padding with randomization
func (p *PaddingCalculator) CalculatePaddedSize(originalSize int64) (int64, error) {
	var blockSize int64

	// Tiered padding based on file size
	switch {
	case originalSize < 1*1024*1024: // < 1MB
		blockSize = 64 * 1024 // 64KB blocks
	case originalSize < 100*1024*1024: // < 100MB
		blockSize = 1024 * 1024 // 1MB blocks
	case originalSize < 1024*1024*1024: // < 1GB
		blockSize = 10 * 1024 * 1024 // 10MB blocks
	default:
		blockSize = 100 * 1024 * 1024 // 100MB blocks
	}

	// Generate cryptographically secure random padding (0-10% of block size)
	maxRandom := big.NewInt(blockSize / 10)
	randomPadding, err := rand.Int(rand.Reader, maxRandom)
	if err != nil {
		return 0, fmt.Errorf("failed to generate random padding: %w", err)
	}

	// Round up to block size and add random component
	padded := ((originalSize + blockSize - 1) / blockSize) * blockSize
	return padded + randomPadding.Int64(), nil
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
