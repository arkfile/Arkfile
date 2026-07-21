package models

import (
	"testing"

	"github.com/arkfile/Arkfile/crypto"
)

func TestCalculateChunkCount(t *testing.T) {
	chunkSize := crypto.PlaintextChunkSize()
	overhead := int64(crypto.AesGcmOverhead())
	encryptedSpan := chunkSize + overhead

	sixGiB := int64(6 * 1024 * 1024 * 1024) // 6442450944
	if sixGiB != 6442450944 {
		t.Fatalf("expected 6GiB constant 6442450944, got %d", sixGiB)
	}

	tests := []struct {
		name      string
		sizeBytes int64
		want      int64
	}{
		{name: "empty", sizeBytes: 0, want: 1},
		{name: "one_byte", sizeBytes: 1, want: 1},
		{name: "chunkSize_minus_one", sizeBytes: chunkSize - 1, want: 1},
		{name: "exact_chunkSize", sizeBytes: chunkSize, want: 1},
		{name: "chunkSize_plus_one", sizeBytes: chunkSize + 1, want: 1},
		{name: "exact_one_encrypted_span", sizeBytes: encryptedSpan, want: 1},
		{name: "one_past_encrypted_span", sizeBytes: encryptedSpan + 1, want: 2},
		{name: "three_exact_encrypted_spans", sizeBytes: 3 * encryptedSpan, want: 3},
		{name: "six_gib", sizeBytes: sixGiB, want: (sixGiB + encryptedSpan - 1) / encryptedSpan},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateChunkCount(tt.sizeBytes, chunkSize)
			if got != tt.want {
				t.Fatalf("CalculateChunkCount(%d, %d) = %d, want %d (overhead=%d span=%d)",
					tt.sizeBytes, chunkSize, got, tt.want, overhead, encryptedSpan)
			}
		})
	}
}

func TestCalculateChunkCount_DefaultChunkSize(t *testing.T) {
	chunkSize := crypto.PlaintextChunkSize()
	overhead := int64(crypto.AesGcmOverhead())
	encryptedSpan := chunkSize + overhead

	got := CalculateChunkCount(encryptedSpan, 0)
	if got != 1 {
		t.Fatalf("CalculateChunkCount with chunkSizeBytes=0: got %d, want 1", got)
	}
}

func TestCalculateChunkCount_SixGiBPlaintextEncryptedStream(t *testing.T) {
	// Representative 6 GiB plaintext is an exact multiple of the configured plaintext chunk size.
	chunkSize := crypto.PlaintextChunkSize()
	overhead := int64(crypto.AesGcmOverhead())
	plaintextSize := int64(6 * 1024 * 1024 * 1024) // 6442450944
	if plaintextSize%chunkSize != 0 {
		t.Fatalf("expected 6GiB to be an exact multiple of plaintext chunk size %d", chunkSize)
	}
	plaintextChunks := plaintextSize / chunkSize
	encryptedSize := plaintextChunks * (chunkSize + overhead)

	got := CalculateChunkCount(encryptedSize, chunkSize)
	if got != plaintextChunks {
		t.Fatalf("6GiB encrypted stream: got %d chunks, want %d (encryptedSize=%d)", got, plaintextChunks, encryptedSize)
	}
}
