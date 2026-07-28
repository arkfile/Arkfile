package crypto

import (
	"encoding/base64"
	"testing"
)

var (
	benchmarkBytes         []byte
	benchmarkShareEnvelope *ShareEnvelope
)

func BenchmarkChunkEncryptGCMWithAAD(b *testing.B) {
	plaintext := make([]byte, PlaintextChunkSize())
	key := make([]byte, 32)
	aad := BuildChunkAAD("12345678-90ab-cdef-1234-567890abcdef", 0, 1)

	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := EncryptGCMWithAAD(plaintext, key, aad)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkBytes = encrypted
	}
}

func BenchmarkChunkDecryptGCMWithAAD(b *testing.B) {
	plaintext := make([]byte, PlaintextChunkSize())
	key := make([]byte, 32)
	aad := BuildChunkAAD("12345678-90ab-cdef-1234-567890abcdef", 0, 1)
	encrypted, err := EncryptGCMWithAAD(plaintext, key, aad)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decrypted, err := DecryptGCMWithAAD(encrypted, key, aad)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkBytes = decrypted
	}
}

func BenchmarkFEKWrap(b *testing.B) {
	fek := make([]byte, 32)
	password := []byte("ArkfileBenchmarkPassword-2026!")
	salt := make([]byte, OwnerEnvelopeSaltSize())
	fileID := "12345678-90ab-cdef-1234-567890abcdef"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := EncryptFEK(fek, password, salt, fileID, AccountKDFContext)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkBytes = encrypted
	}
}

func BenchmarkFEKUnwrap(b *testing.B) {
	fek := make([]byte, 32)
	password := []byte("ArkfileBenchmarkPassword-2026!")
	salt := make([]byte, OwnerEnvelopeSaltSize())
	fileID := "12345678-90ab-cdef-1234-567890abcdef"
	encrypted, err := EncryptFEK(fek, password, salt, fileID, AccountKDFContext)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decrypted, _, err := DecryptFEK(encrypted, password, fileID)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkBytes = decrypted
	}
}

func BenchmarkDeriveShareKey(b *testing.B) {
	password := "ArkfileShareBenchmarkPassword-2026!"
	salt := base64.StdEncoding.EncodeToString(make([]byte, ShareKDFParams.SaltLength))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, err := DeriveShareKey(password, salt)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkBytes = key
	}
}

func BenchmarkShareEnvelopeCreate(b *testing.B) {
	fek := make([]byte, 32)
	token := make([]byte, 32)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		envelope, err := CreateShareEnvelope(
			fek,
			token,
			"benchmark.bin",
			PlaintextChunkSize(),
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkBytes = envelope
	}
}

func BenchmarkShareEnvelopeParse(b *testing.B) {
	envelope, err := CreateShareEnvelope(
		make([]byte, 32),
		make([]byte, 32),
		"benchmark.bin",
		PlaintextChunkSize(),
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parsed, err := ParseShareEnvelope(envelope)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkShareEnvelope = parsed
	}
}

func BenchmarkShareEnvelopeSeal(b *testing.B) {
	envelope, err := CreateShareEnvelope(
		make([]byte, 32),
		make([]byte, 32),
		"benchmark.bin",
		PlaintextChunkSize(),
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	)
	if err != nil {
		b.Fatal(err)
	}
	key := make([]byte, 32)
	aad := CreateAAD("share-benchmark", "file-benchmark")

	b.ReportAllocs()
	b.SetBytes(int64(len(envelope)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := EncryptGCMWithAAD(envelope, key, aad)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkBytes = encrypted
	}
}

func BenchmarkShareEnvelopeOpen(b *testing.B) {
	envelope, err := CreateShareEnvelope(
		make([]byte, 32),
		make([]byte, 32),
		"benchmark.bin",
		PlaintextChunkSize(),
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	)
	if err != nil {
		b.Fatal(err)
	}
	key := make([]byte, 32)
	aad := CreateAAD("share-benchmark", "file-benchmark")
	encrypted, err := EncryptGCMWithAAD(envelope, key, aad)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(envelope)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plaintext, err := DecryptGCMWithAAD(encrypted, key, aad)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkBytes = plaintext
	}
}
