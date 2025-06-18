package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashPassword_BasicFunctionality(t *testing.T) {
	password := "SecurePassword123!"

	hash, err := HashPassword(password)
	require.NoError(t, err, "HashPassword should not return an error")
	require.NotEmpty(t, hash, "Hash should not be empty")

	// Verify the password can be verified against its hash
	isValid := VerifyPassword(password, hash)
	assert.True(t, isValid, "Password should verify against its hash")

	// Verify wrong password fails
	isValid = VerifyPassword("WrongPassword123!", hash)
	assert.False(t, isValid, "Wrong password should not verify")
}

func TestHashPassword_EmptyPassword(t *testing.T) {
	hash, err := HashPassword("")
	require.NoError(t, err, "HashPassword should handle empty password")
	require.NotEmpty(t, hash, "Hash should not be empty even for empty password")

	// Empty password should verify against its hash
	isValid := VerifyPassword("", hash)
	assert.True(t, isValid, "Empty password should verify against its hash")
}

func TestHashPassword_LongPassword(t *testing.T) {
	// Test with very long password (1000 characters)
	longPassword := strings.Repeat("a", 1000)

	hash, err := HashPassword(longPassword)
	require.NoError(t, err, "HashPassword should handle long passwords")
	require.NotEmpty(t, hash, "Hash should not be empty for long password")

	isValid := VerifyPassword(longPassword, hash)
	assert.True(t, isValid, "Long password should verify against its hash")
}

func TestHashPassword_UnicodePassword(t *testing.T) {
	// Test with Unicode characters
	password := "🔒🌟Password123!中文ñáéíóú"

	hash, err := HashPassword(password)
	require.NoError(t, err, "HashPassword should handle Unicode passwords")
	require.NotEmpty(t, hash, "Hash should not be empty for Unicode password")

	isValid := VerifyPassword(password, hash)
	assert.True(t, isValid, "Unicode password should verify against its hash")
}

func TestHashPassword_Deterministic(t *testing.T) {
	password := "TestPassword123!"

	// Hash the same password multiple times
	hash1, err1 := HashPassword(password)
	hash2, err2 := HashPassword(password)
	hash3, err3 := HashPassword(password)

	require.NoError(t, err1)
	require.NoError(t, err2)
	require.NoError(t, err3)

	// Hashes should be different (due to random salt)
	assert.NotEqual(t, hash1, hash2, "Hashes should be different due to random salt")
	assert.NotEqual(t, hash2, hash3, "Hashes should be different due to random salt")
	assert.NotEqual(t, hash1, hash3, "Hashes should be different due to random salt")

	// But all should verify the same password
	assert.True(t, VerifyPassword(password, hash1), "Password should verify against hash1")
	assert.True(t, VerifyPassword(password, hash2), "Password should verify against hash2")
	assert.True(t, VerifyPassword(password, hash3), "Password should verify against hash3")
}

func TestHashPassword_Format(t *testing.T) {
	password := "FormatTest123!"

	hash, err := HashPassword(password)
	require.NoError(t, err)

	// Argon2ID hash should start with $argon2id$
	assert.True(t, strings.HasPrefix(hash, "$argon2id$"), "Hash should be in Argon2ID format")

	// Should contain expected number of $ separators (5 total: $argon2id$v=19$m=65536,t=3,p=4$salt$hash)
	parts := strings.Split(hash, "$")
	assert.Len(t, parts, 6, "Hash should have 6 parts separated by $")
	assert.Equal(t, "", parts[0], "First part should be empty")
	assert.Equal(t, "argon2id", parts[1], "Second part should be 'argon2id'")
	assert.Equal(t, "v=19", parts[2], "Third part should be 'v=19' (version)")

	// Check parameters format (m=memory,t=time,p=parallelism)
	params := parts[3]
	assert.Contains(t, params, "m=", "Parameters should contain memory setting")
	assert.Contains(t, params, "t=", "Parameters should contain time setting")
	assert.Contains(t, params, "p=", "Parameters should contain parallelism setting")
}

func TestVerifyPassword_InvalidHashes(t *testing.T) {
	password := "TestPassword123!"

	testCases := []struct {
		name string
		hash string
	}{
		{"Empty hash", ""},
		{"Invalid format", "invalid-hash"},
		{"Wrong algorithm", "$2b$12$invalid"},
		{"Malformed argon2id", "$argon2id$invalid"},
		{"Truncated hash", "$argon2id$v=19$m=65536,t=3,p=4$"},
		{"Invalid base64", "$argon2id$v=19$m=65536,t=3,p=4$invalidbase64$invalidbase64"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isValid := VerifyPassword(password, tc.hash)
			assert.False(t, isValid, "Invalid hash should not verify")
		})
	}
}

func TestHashPassword_Performance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	password := "PerformanceTest123!"

	// Measure hashing time
	start := time.Now()
	hash, err := HashPassword(password)
	hashDuration := time.Since(start)

	require.NoError(t, err)
	require.NotEmpty(t, hash)

	// Hashing should take reasonable time (not too fast, not too slow)
	// Argon2ID with our parameters should take 100ms-2000ms on reasonable hardware
	assert.True(t, hashDuration > 50*time.Millisecond, "Hashing should take at least 50ms for security")
	assert.True(t, hashDuration < 5*time.Second, "Hashing should not take more than 5 seconds")

	// Measure verification time
	start = time.Now()
	isValid := VerifyPassword(password, hash)
	verifyDuration := time.Since(start)

	assert.True(t, isValid, "Password should verify")
	// Verification should be similar to hashing time
	assert.True(t, verifyDuration > 50*time.Millisecond, "Verification should take at least 50ms")
	assert.True(t, verifyDuration < 5*time.Second, "Verification should not take more than 5 seconds")

	t.Logf("Hash time: %v, Verify time: %v", hashDuration, verifyDuration)
}

func TestHashPassword_MemoryUsage(t *testing.T) {
	password := "MemoryTest123!"

	// This test ensures the function doesn't panic with memory allocation
	// and that it properly uses the configured memory parameters
	hash, err := HashPassword(password)
	require.NoError(t, err)
	require.NotEmpty(t, hash)

	// Verify that the hash contains our expected memory parameter
	// Server config should use 131072 KB (128 MB)
	assert.Contains(t, hash, "m=131072", "Hash should contain expected memory parameter")
}

func TestHashPassword_ConcurrentSafety(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrency test in short mode")
	}

	password := "ConcurrentTest123!"
	numGoroutines := 10

	results := make(chan struct {
		hash string
		err  error
	}, numGoroutines)

	// Start multiple goroutines hashing the same password
	for i := 0; i < numGoroutines; i++ {
		go func() {
			hash, err := HashPassword(password)
			results <- struct {
				hash string
				err  error
			}{hash, err}
		}()
	}

	// Collect results
	hashes := make([]string, 0, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		result := <-results
		require.NoError(t, result.err, "Concurrent hashing should not error")
		require.NotEmpty(t, result.hash, "Concurrent hashing should produce valid hash")
		hashes = append(hashes, result.hash)
	}

	// All hashes should be different (due to random salt)
	hashSet := make(map[string]bool)
	for _, hash := range hashes {
		assert.False(t, hashSet[hash], "Each concurrent hash should be unique")
		hashSet[hash] = true

		// Each hash should verify the original password
		assert.True(t, VerifyPassword(password, hash), "Each concurrent hash should verify")
	}
}

func TestHashPassword_ParameterConfiguration(t *testing.T) {
	password := "ConfigTest123!"

	hash, err := HashPassword(password)
	require.NoError(t, err)
	require.NotEmpty(t, hash)

	// Extract and verify parameters from hash
	parts := strings.Split(hash, "$")
	require.Len(t, parts, 6)

	params := parts[3] // m=131072,t=4,p=4

	// Check that our server configuration is being used
	expectedParams := []string{
		"m=131072", // 128MB memory
		"t=4",      // 4 time iterations
		"p=4",      // 4 parallel threads
	}

	for _, expected := range expectedParams {
		assert.Contains(t, params, expected, "Hash should contain expected parameter: %s", expected)
	}
}

func TestVerifyPassword_TimingAttackResistance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timing attack test in short mode")
	}

	password := "TimingTest123!"
	hash, err := HashPassword(password)
	require.NoError(t, err)

	// Test verification times for correct vs incorrect passwords
	// This is a basic check - in reality timing attack resistance
	// is more complex and depends on constant-time implementations

	correctTimes := make([]time.Duration, 5)
	incorrectTimes := make([]time.Duration, 5)

	// Measure correct password verification times
	for i := 0; i < 5; i++ {
		start := time.Now()
		isValid := VerifyPassword(password, hash)
		correctTimes[i] = time.Since(start)
		assert.True(t, isValid, "Correct password should verify")
	}

	// Measure incorrect password verification times
	for i := 0; i < 5; i++ {
		start := time.Now()
		isValid := VerifyPassword("WrongPassword123!", hash)
		incorrectTimes[i] = time.Since(start)
		assert.False(t, isValid, "Incorrect password should not verify")
	}

	// Both should take similar time (within reasonable variance)
	// This is a basic sanity check - real timing attack resistance
	// requires more sophisticated analysis
	var correctAvg, incorrectAvg time.Duration
	for i := 0; i < 5; i++ {
		correctAvg += correctTimes[i]
		incorrectAvg += incorrectTimes[i]
	}
	correctAvg /= 5
	incorrectAvg /= 5

	t.Logf("Average correct verification time: %v", correctAvg)
	t.Logf("Average incorrect verification time: %v", incorrectAvg)

	// Times should be within reasonable variance of each other
	ratio := float64(correctAvg) / float64(incorrectAvg)
	assert.True(t, ratio > 0.5 && ratio < 2.0, "Verification times should be similar for timing attack resistance")
}

func TestHashPassword_SaltUniqueness(t *testing.T) {
	password := "SaltTest123!"
	numHashes := 100

	salts := make(map[string]bool)

	for i := 0; i < numHashes; i++ {
		hash, err := HashPassword(password)
		require.NoError(t, err)

		// Extract salt from hash
		parts := strings.Split(hash, "$")
		require.Len(t, parts, 6)
		salt := parts[4]

		// Check salt uniqueness
		assert.False(t, salts[salt], "Salt should be unique across multiple hashes")
		salts[salt] = true

		// Salt should be properly base64 encoded and reasonable length
		assert.True(t, len(salt) > 10, "Salt should be reasonable length")
	}

	assert.Len(t, salts, numHashes, "All salts should be unique")
}

// Benchmark tests
func BenchmarkHashPassword(b *testing.B) {
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := HashPassword(password)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	password := "BenchmarkPassword123!"
	hash, err := HashPassword(password)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !VerifyPassword(password, hash) {
			b.Fatal("Password verification failed")
		}
	}
}
