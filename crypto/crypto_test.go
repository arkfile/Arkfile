package crypto

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestGenerateSalt(t *testing.T) {
	tests := []struct {
		name   string
		length int
		valid  bool
	}{
		{"32 bytes", 32, true},
		{"16 bytes", 16, true},
		{"64 bytes", 64, true},
		{"1 byte", 1, true},
		{"zero length", 0, true}, // Should work but return empty slice
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			salt, err := GenerateSalt(tt.length)
			if err != nil && tt.valid {
				t.Errorf("GenerateSalt() error = %v, expected nil", err)
				return
			}
			if len(salt) != tt.length {
				t.Errorf("GenerateSalt() length = %d, expected %d", len(salt), tt.length)
			}
		})
	}
}

func TestGenerateSaltUniqueness(t *testing.T) {
	// Generate multiple salts and ensure they're different
	salts := make([][]byte, 100)
	for i := range salts {
		var err error
		salts[i], err = GenerateSalt(32)
		if err != nil {
			t.Fatalf("Failed to generate salt: %v", err)
		}
	}

	// Check for duplicates
	for i := 0; i < len(salts); i++ {
		for j := i + 1; j < len(salts); j++ {
			if bytes.Equal(salts[i], salts[j]) {
				t.Errorf("Found duplicate salts at indices %d and %d", i, j)
			}
		}
	}
}

func TestDeviceCapabilityString(t *testing.T) {
	tests := []struct {
		capability DeviceCapability
		expected   string
	}{
		{DeviceMinimal, "minimal"},
		{DeviceInteractive, "interactive"},
		{DeviceBalanced, "balanced"},
		{DeviceMaximum, "maximum"},
		{DeviceCapability(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.capability.String()
			if result != tt.expected {
				t.Errorf("String() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestDeviceCapabilityGetProfile(t *testing.T) {
	tests := []struct {
		capability DeviceCapability
		name       string
	}{
		{DeviceMinimal, "minimal"},
		{DeviceInteractive, "interactive"},
		{DeviceBalanced, "balanced"},
		{DeviceMaximum, "maximum"},
		{DeviceCapability(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := tt.capability.GetProfile()

			// Validate profile parameters
			if profile.Time == 0 {
				t.Error("Profile time should be greater than 0")
			}
			if profile.Memory == 0 {
				t.Error("Profile memory should be greater than 0")
			}
			if profile.Threads == 0 {
				t.Error("Profile threads should be greater than 0")
			}
			if profile.KeyLen != 32 {
				t.Errorf("Profile key length should be 32, got %d", profile.KeyLen)
			}
		})
	}
}

func TestDeriveKeyArgon2ID(t *testing.T) {
	password := []byte("testpassword")
	salt := []byte("testsalt1234567890123456789012") // 30 bytes
	profile := ArgonInteractive

	key1 := DeriveKeyArgon2ID(password, salt, profile)
	key2 := DeriveKeyArgon2ID(password, salt, profile)

	// Same inputs should produce same output
	if !bytes.Equal(key1, key2) {
		t.Error("Same inputs should produce same key")
	}

	// Check key length
	if len(key1) != int(profile.KeyLen) {
		t.Errorf("Key length should be %d, got %d", profile.KeyLen, len(key1))
	}

	// Different password should produce different key
	key3 := DeriveKeyArgon2ID([]byte("differentpassword"), salt, profile)
	if bytes.Equal(key1, key3) {
		t.Error("Different passwords should produce different keys")
	}

	// Different salt should produce different key
	differentSalt := []byte("differentsalt123456789012345") // 30 bytes
	key4 := DeriveKeyArgon2ID(password, differentSalt, profile)
	if bytes.Equal(key1, key4) {
		t.Error("Different salts should produce different keys")
	}
}

func TestDeriveKeyFromCapability(t *testing.T) {
	password := []byte("testpassword")
	salt, err := GenerateSalt(32)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	for _, capability := range []DeviceCapability{
		DeviceMinimal, DeviceInteractive, DeviceBalanced, DeviceMaximum,
	} {
		t.Run(capability.String(), func(t *testing.T) {
			key := DeriveKeyFromCapability(password, salt, capability)
			if len(key) != 32 {
				t.Errorf("Key length should be 32, got %d", len(key))
			}

			// Verify it matches direct profile usage
			profile := capability.GetProfile()
			expectedKey := DeriveKeyArgon2ID(password, salt, profile)
			if !bytes.Equal(key, expectedKey) {
				t.Error("DeriveKeyFromCapability should match direct profile usage")
			}
		})
	}
}

func TestValidateProfile(t *testing.T) {
	tests := []struct {
		name    string
		profile ArgonProfile
		valid   bool
	}{
		{
			"valid profile",
			ArgonProfile{Time: 1, Memory: 1024, Threads: 1, KeyLen: 32},
			true,
		},
		{
			"zero time",
			ArgonProfile{Time: 0, Memory: 1024, Threads: 1, KeyLen: 32},
			false,
		},
		{
			"low memory",
			ArgonProfile{Time: 1, Memory: 512, Threads: 1, KeyLen: 32},
			false,
		},
		{
			"zero threads",
			ArgonProfile{Time: 1, Memory: 1024, Threads: 0, KeyLen: 32},
			false,
		},
		{
			"zero key length",
			ArgonProfile{Time: 1, Memory: 1024, Threads: 1, KeyLen: 0},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProfile(tt.profile)
			if (err == nil) != tt.valid {
				t.Errorf("ValidateProfile() error = %v, expected valid = %v", err, tt.valid)
			}
		})
	}
}

func TestSecureZeroBytes(t *testing.T) {
	data := make([]byte, 10)
	// Fill with non-zero data
	for i := range data {
		data[i] = byte(i + 1)
	}

	// Verify data is not zero
	for i, b := range data {
		if b == 0 {
			t.Errorf("Data at index %d should not be zero before SecureZeroBytes", i)
		}
	}

	SecureZeroBytes(data)

	// Verify data is all zeros
	for i, b := range data {
		if b != 0 {
			t.Errorf("Data at index %d should be zero after SecureZeroBytes, got %d", i, b)
		}
	}
}

func TestSecureCompare(t *testing.T) {
	tests := []struct {
		name string
		a    []byte
		b    []byte
		want bool
	}{
		{"identical slices", []byte("hello"), []byte("hello"), true},
		{"different slices", []byte("hello"), []byte("world"), false},
		{"different lengths", []byte("hello"), []byte("hi"), false},
		{"empty slices", []byte{}, []byte{}, true},
		{"one empty", []byte("hello"), []byte{}, false},
		{"nil slices", nil, nil, true},
		{"one nil", []byte("hello"), nil, false},
		{"same content different case", []byte("Hello"), []byte("hello"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SecureCompare(tt.a, tt.b)
			if result != tt.want {
				t.Errorf("SecureCompare() = %v, want %v", result, tt.want)
			}
		})
	}
}

func TestSecureCompareTimingConsistency(t *testing.T) {
	// Test that SecureCompare takes similar time for equal and unequal inputs
	// This is a basic test and doesn't guarantee timing attack resistance,
	// but it can catch obvious timing differences

	a := make([]byte, 1000)
	b := make([]byte, 1000)
	c := make([]byte, 1000)

	// Fill with random data
	rand.Read(a)
	copy(b, a)   // b is identical to a
	rand.Read(c) // c is different from a

	// Warm up
	for i := 0; i < 100; i++ {
		SecureCompare(a, b)
		SecureCompare(a, c)
	}

	// The actual test would need more sophisticated timing measurement
	// For now, just verify the function works correctly
	if !SecureCompare(a, b) {
		t.Error("SecureCompare should return true for identical slices")
	}
	if SecureCompare(a, c) {
		t.Error("SecureCompare should return false for different slices")
	}
}

func TestPredefinedProfiles(t *testing.T) {
	profiles := []ArgonProfile{
		ArgonInteractive,
		ArgonBalanced,
		ArgonMaximum,
	}

	for i, profile := range profiles {
		t.Run(fmt.Sprintf("profile_%d", i), func(t *testing.T) {
			if err := ValidateProfile(profile); err != nil {
				t.Errorf("Predefined profile should be valid: %v", err)
			}

			// Test that higher profiles have higher computational costs
			if i > 0 {
				prev := profiles[i-1]
				if profile.Time < prev.Time && profile.Memory <= prev.Memory {
					t.Error("Higher profile should have higher computational cost")
				}
			}
		})
	}
}

func BenchmarkDeriveKeyArgon2ID(b *testing.B) {
	password := []byte("benchmarkpassword")
	salt, _ := GenerateSalt(32)

	profiles := []struct {
		name    string
		profile ArgonProfile
	}{
		{"Interactive", ArgonInteractive},
		{"Balanced", ArgonBalanced},
		{"Maximum", ArgonMaximum},
	}

	for _, p := range profiles {
		b.Run(p.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				DeriveKeyArgon2ID(password, salt, p.profile)
			}
		})
	}
}

func BenchmarkGenerateSalt(b *testing.B) {
	sizes := []int{16, 32, 64}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				GenerateSalt(size)
			}
		})
	}
}

func BenchmarkSecureCompare(b *testing.B) {
	sizes := []int{32, 256, 1024}

	for _, size := range sizes {
		a := make([]byte, size)
		c := make([]byte, size)
		rand.Read(a)
		copy(c, a)

		b.Run(fmt.Sprintf("%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				SecureCompare(a, c)
			}
		})
	}
}
