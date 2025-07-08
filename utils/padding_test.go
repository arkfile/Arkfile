package utils

import (
	"testing"
)

func TestPaddingCalculator(t *testing.T) {
	tests := []struct {
		name         string
		originalSize int64
		minExpected  int64
		maxExpected  int64
	}{
		{
			name:         "Small file (< 1MB)",
			originalSize: 1024,         // 1KB
			minExpected:  65536,        // 64KB block
			maxExpected:  65536 + 6553, // 64KB + 10% (6.4KB)
		},
		{
			name:         "Small file near block boundary",
			originalSize: 65536,        // exactly 64KB
			minExpected:  65536,        // 64KB block
			maxExpected:  65536 + 6553, // 64KB + 10%
		},
		{
			name:         "Medium file (1-100MB)",
			originalSize: 50 * 1024 * 1024,      // 50MB
			minExpected:  50 * 1024 * 1024,      // 50MB (rounded to 1MB block)
			maxExpected:  50*1024*1024 + 102400, // 50MB + 10% of 1MB
		},
		{
			name:         "Large file (100MB-1GB)",
			originalSize: 500 * 1024 * 1024,         // 500MB
			minExpected:  500 * 1024 * 1024,         // 500MB (rounded to 10MB block)
			maxExpected:  500*1024*1024 + 1024*1024, // 500MB + 10% of 10MB
		},
		{
			name:         "Very large file (> 1GB)",
			originalSize: 2 * 1024 * 1024 * 1024,        // 2GB
			minExpected:  2 * 1024 * 1024 * 1024,        // 2GB (rounded to 100MB block)
			maxExpected:  2100*1024*1024 + 10*1024*1024, // 2100MB (rounded up) + 10% of 100MB
		},
	}

	calc := NewPaddingCalculator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded, err := calc.CalculatePaddedSize(tt.originalSize)
			if err != nil {
				t.Fatalf("CalculatePaddedSize failed: %v", err)
			}

			if padded < tt.minExpected {
				t.Errorf("Padded size %d is less than minimum expected %d", padded, tt.minExpected)
			}

			if padded > tt.maxExpected {
				t.Errorf("Padded size %d is greater than maximum expected %d", padded, tt.maxExpected)
			}

			// Verify padding is always >= original size
			if padded < tt.originalSize {
				t.Errorf("Padded size %d is less than original size %d", padded, tt.originalSize)
			}
		})
	}
}

func TestGeneratePaddingBytes(t *testing.T) {
	calc := NewPaddingCalculator()

	tests := []struct {
		name string
		size int64
	}{
		{"Zero size", 0},
		{"Small padding", 100},
		{"Large padding", 1024 * 1024}, // 1MB
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padding, err := calc.GeneratePaddingBytes(tt.size)
			if err != nil {
				t.Fatalf("GeneratePaddingBytes failed: %v", err)
			}

			if int64(len(padding)) != tt.size {
				t.Errorf("Expected padding of size %d, got %d", tt.size, len(padding))
			}

			// For non-zero sizes, verify randomness (not all zeros)
			if tt.size > 0 {
				allZeros := true
				for _, b := range padding {
					if b != 0 {
						allZeros = false
						break
					}
				}
				if allZeros {
					t.Error("Padding bytes are all zeros, expected random data")
				}
			}
		})
	}
}

func TestGetPaddingSize(t *testing.T) {
	calc := NewPaddingCalculator()

	tests := []struct {
		name         string
		originalSize int64
		targetSize   int64
		expected     int64
	}{
		{"No padding needed", 100, 100, 0},
		{"Target smaller than original", 100, 50, 0},
		{"Standard padding", 100, 200, 100},
		{"Large padding", 1024, 65536, 64512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paddingSize := calc.GetPaddingSize(tt.originalSize, tt.targetSize)
			if paddingSize != tt.expected {
				t.Errorf("Expected padding size %d, got %d", tt.expected, paddingSize)
			}
		})
	}
}

func TestPaddingConsistency(t *testing.T) {
	calc := NewPaddingCalculator()

	// Test that multiple calls with same size produce different results (due to randomization)
	originalSize := int64(1024 * 1024) // 1MB
	results := make(map[int64]bool)

	for i := 0; i < 10; i++ {
		padded, err := calc.CalculatePaddedSize(originalSize)
		if err != nil {
			t.Fatalf("CalculatePaddedSize failed: %v", err)
		}
		results[padded] = true
	}

	// We should have at least 2 different results due to randomization
	if len(results) < 2 {
		t.Error("Expected different padded sizes due to randomization, but got consistent results")
	}
}

func BenchmarkCalculatePaddedSize(b *testing.B) {
	calc := NewPaddingCalculator()
	sizes := []int64{
		1024,               // 1KB
		1024 * 1024,        // 1MB
		100 * 1024 * 1024,  // 100MB
		1024 * 1024 * 1024, // 1GB
	}

	for _, size := range sizes {
		b.Run(formatSize(size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := calc.CalculatePaddedSize(size)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkGeneratePaddingBytes(b *testing.B) {
	calc := NewPaddingCalculator()
	sizes := []int64{
		1024,        // 1KB
		64 * 1024,   // 64KB
		1024 * 1024, // 1MB
	}

	for _, size := range sizes {
		b.Run(formatSize(size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := calc.GeneratePaddingBytes(size)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return string(rune(bytes)) + "B"
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return string(rune(bytes/div)) + string("KMGTPE"[exp]) + "B"
}
