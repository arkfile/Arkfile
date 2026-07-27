package models

import (
	"testing"

	"github.com/arkfile/Arkfile/crypto"
)

func TestCalculateChunkCount(t *testing.T) {
	chunkSize := crypto.PlaintextChunkSize()
	overhead := int64(crypto.AesGcmOverhead())
	encryptedSpan := chunkSize + overhead

	fiveChunks := int64(5) * chunkSize

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
		{name: "five_plaintext_chunks", sizeBytes: fiveChunks, want: (fiveChunks + encryptedSpan - 1) / encryptedSpan},
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

func TestCalculateChunkCount_BoundedPlaintextEncryptedStream(t *testing.T) {
	chunkSize := crypto.PlaintextChunkSize()
	overhead := int64(crypto.AesGcmOverhead())
	plaintextSize := int64(5) * chunkSize
	plaintextChunks := plaintextSize / chunkSize
	encryptedSize := plaintextChunks * (chunkSize + overhead)

	got := CalculateChunkCount(encryptedSize, chunkSize)
	if got != plaintextChunks {
		t.Fatalf("bounded encrypted stream: got %d chunks, want %d (encryptedSize=%d)", got, plaintextChunks, encryptedSize)
	}
}
